import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

FIELDS = ("ip", "port", "hostname", "service", "version", "players", "motd", "observation")


def port_range(value):
    if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", value):
        raise argparse.ArgumentTypeError("Use a port or range such as 25565-25688.")
    first, _, last = value.partition("-")
    start, end = int(first), int(last or first)
    if not 1 <= start <= end <= 65535:
        raise argparse.ArgumentTypeError("Ports must be ordered and between 1 and 65535.")
    return range(start, end + 1)


def resolve_domain(host):
    # Use Windows DNS so the lookup follows the same network settings as the game.
    env = dict(os.environ, MINECRAFT_SCAN_HOST=host)
    command = (
        "Resolve-DnsName -Name ('_minecraft._tcp.' + $env:MINECRAFT_SCAN_HOST) "
        "-Type SRV -DnsOnly -ErrorAction SilentlyContinue | "
        "Where-Object Type -eq SRV | ForEach-Object { "
        '"$($_.NameTarget) $($_.Port)" }'
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env=env, capture_output=True, text=True, timeout=10,
    )
    records = []
    for line in result.stdout.splitlines():
        name, port = line.split()
        if name != ".":
            records.append((name.rstrip("."), int(port)))
    return records


def build_targets(values, prefix):
    networks = []
    routes = set()
    for value in values:
        if value.endswith(".*"):
            value = value[:-1] + "0/24"
        try:
            network = ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            if "/" in value or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
                raise ValueError(f"Invalid IPv4 range or hostname: {value}")
            records = resolve_domain(value)
            for name, port in records or [(value, 25565)]:
                for _, _, _, _, address in socket.getaddrinfo(
                    name, port, socket.AF_INET, socket.SOCK_STREAM
                ):
                    ip, resolved_port = address
                    routes.add((ip, resolved_port, value))
                    networks.append(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
        else:
            if "/" not in value:
                network = ipaddress.IPv4Network(f"{value}/{prefix}", strict=False)
            networks.append(network)
    return list(ipaddress.collapse_addresses(networks)), routes


def jobs(networks, routes, ports):
    yield from sorted(routes)
    route_endpoints = {(ip, port) for ip, port, _ in routes}
    for network in networks:
        for address in network:
            ip = str(address)
            for port in ports:
                if (ip, port) not in route_endpoints:
                    yield ip, port, ip


def varint(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data) + bytes([value])


def read_varint(stream):
    value = 0
    for shift in range(0, 35, 7):
        byte = stream.read(1)
        if not byte:
            raise EOFError
        value |= (byte[0] & 127) << shift
        if byte[0] < 128:
            return value
    raise ValueError("Invalid VarInt")


def minecraft_status(sock, hostname, port):
    host = hostname.encode("ascii")
    handshake = b"\x00" + varint(767) + varint(len(host)) + host
    handshake += struct.pack(">H", port) + b"\x01"
    sock.sendall(varint(len(handshake)) + handshake + b"\x01\x00")
    with sock.makefile("rb") as stream:
        length = read_varint(stream)
        if not 1 <= length <= 131072 or read_varint(stream) != 0:
            raise ValueError("Unexpected packet")
        size = read_varint(stream)
        if not 1 <= size <= length:
            raise ValueError("Unexpected status length")
        status = json.loads(stream.read(size))
        if not isinstance(status, dict) or not isinstance(status.get("version"), dict):
            raise ValueError("Unexpected status")
        return status


def plain_text(component):
    if isinstance(component, str):
        return component
    if isinstance(component, list):
        return "".join(map(plain_text, component))
    if isinstance(component, dict):
        return plain_text(component.get("text", "")) + plain_text(component.get("extra", []))
    return ""


def probe(job, timeout):
    ip, port, hostname = job
    try:
        sock = socket.create_connection((ip, port), timeout)
    except OSError:
        return None

    row = dict(ip=ip, port=port, hostname=hostname, service="TCP open",
               observation="Minecraft Java status unconfirmed")
    with sock:
        try:
            status = minecraft_status(sock, hostname, port)
        except (OSError, EOFError, ValueError, RecursionError):
            return row

    version = str(status["version"].get("name", ""))
    players = status.get("players")
    motd = re.sub(r"\xa7.", "", plain_text(status.get("description")))
    row.update(service="Minecraft Java", version=version, motd=motd,
               observation="Public status response; access controls unverified")
    if isinstance(players, dict):
        row["players"] = f"{players.get('online', '?')}/{players.get('max', '?')}"
    if any(proxy in version.lower() for proxy in ("velocity", "bungeecord", "waterfall")):
        row["observation"] = "Proxy advertised; backend addresses and access controls unverified"
    return row


def scan(target_jobs, output, timeout, rate, workers, *, minecraft_only=False, total=None):
    with output.open("x", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        file.flush()
        pending = set()
        completed = matches = 0
        next_report = time.monotonic() + 5

        def report():
            print(f"Progress: {completed:,}/{total:,} attempts completed | "
                  f"{matches:,} Minecraft responses", flush=True)

        def save_completed():
            nonlocal completed, matches, next_report
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            completed += len(done)
            for future in done:
                pending.remove(future)
                row = future.result()
                if row and row["service"] == "Minecraft Java":
                    matches += 1
                if row and (not minecraft_only or row["service"] == "Minecraft Java"):
                    print(f"{row['ip']}:{row['port']} {row['service']} {row.get('version', '')}")
                    # Prevent spreadsheet formulas when opening server-controlled text in Excel.
                    for field in ("version", "motd"):
                        if str(row.get(field, "")).lstrip().startswith(("=", "+", "-", "@")):
                            row[field] = "'" + row[field]
                    writer.writerow(row)
                    file.flush()
            now = time.monotonic()
            if total is not None and now >= next_report and completed < total:
                report()
                next_report = now + 5

        next_start = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for job in target_jobs:
                while len(pending) >= workers:
                    save_completed()
                time.sleep(max(0, next_start - time.monotonic()))
                pending.add(pool.submit(probe, job, timeout))
                next_start = time.monotonic() + 1 / rate
            while pending:
                save_completed()
        if total is not None:
            report()


def main():
    parser = argparse.ArgumentParser(description="Discover Minecraft Java servers on IPv4.")
    parser.add_argument("targets", nargs="+", help="IPv4 addresses, CIDRs or DNS hostnames")
    parser.add_argument("--expand-prefix", type=int, choices=range(24, 33), default=32,
                        metavar="24-32", help="Expand individual IPs to this prefix (default: 32)")
    parser.add_argument("--ports", type=port_range, default="25565",
                        help="TCP port or inclusive range (default: 25565, plus DNS SRV ports)")
    parser.add_argument("--rate", type=int, choices=range(1, 26), default=10,
                        metavar="1-25", help="Connection attempts per second (default: 10)")
    parser.add_argument("--timeout", type=float, default=2, help="Socket timeout in seconds")
    parser.add_argument("--output", type=Path, default=Path("minecraft-scan.csv"))
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 10:
        parser.error("--timeout must be between 0.1 and 10 seconds")
    try:
        networks, routes = build_targets(args.targets, args.expand_prefix)
        addresses = sum(network.num_addresses for network in networks)
        count = addresses * len(args.ports) + len(routes)
        count -= sum(port in args.ports for _, port in {(ip, p) for ip, p, _ in routes})
        print(f"{addresses:,} IPv4 addresses, {count:,} attempts. "
              f"Estimated minimum: {count / args.rate / 60:,.1f} minutes.", flush=True)
        if count > 10000 and input("Type SCAN to start: ").strip() != "SCAN":
            return
        scan(jobs(networks, routes, args.ports), args.output, args.timeout, args.rate, 16)
    except KeyboardInterrupt:
        print(f"Scan interrupted. Any saved results are in {args.output}.")
        raise SystemExit(130)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Scan failed: {error}\n")
    print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
