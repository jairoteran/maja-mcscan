import argparse
import base64
import csv
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime
from itertools import chain, groupby
from pathlib import Path
from tempfile import TemporaryDirectory

sys.dont_write_bytecode = True
import minecraft_scan as scanner


LEGACY_PORTS = (
    "1-20,24-50,100,200,300,400,500,600,700,800,900,666,777,1000-1010,2000-2050,"
    "12345,19132,25500-25600,10001-10020,20001-20020,30000-30005,40001-40010,"
    "50001-50010,60001-60010"
)


def parse_ports(value):
    if value.casefold() == "legacy":
        value = LEGACY_PORTS
    parts = value.split(",")
    if len(parts) == 1:
        return scanner.port_range(value)
    return tuple(sorted({port for part in parts for port in scanner.port_range(part.strip())}))


def display_ports(ports):
    if isinstance(ports, range):
        return f"{ports.start}-{ports.stop - 1}"
    ranges = []
    for _, group in groupby(enumerate(ports), key=lambda item: item[1] - item[0]):
        _, first = next(group)
        last = first
        for _, last in group:
            pass
        ranges.append(str(first) if first == last else f"{first}-{last}")
    return ",".join(ranges)


def audit_network(value):
    network = ipaddress.IPv4Network(value)
    if network.prefixlen < 24:
        raise ValueError("Use an IPv4 address or CIDR between /24 and /32.")
    return network


def confirm_scope(networks, ports):
    scope = ", ".join(map(str, networks))
    return input(f"Confirm the owner approved scanning {scope} on ports "
                 f"{display_ports(ports)} [y/N]: ").strip().lower() == "y"


def audit(args):
    networks = list(ipaddress.collapse_addresses(audit_network(value) for value in args.target))
    if confirm_scope(networks, args.ports):
        scan_targets(networks, args.ports, args.output, args.rate)


def scan_targets(networks, ports, output, rate):
    priority = tuple(port for port in (*range(25565, 25578), 25688) if port in ports)

    def jobs():
        remaining = (port for port in ports if port not in priority)
        for port in chain(priority, remaining):
            for network in networks:
                for address in network:
                    ip = str(address)
                    yield ip, port, ip

    address_count = sum(network.num_addresses for network in networks)
    count = address_count * len(ports)
    print(f"{address_count} approved IPs, {count:,} attempts at up to {rate}/s. "
          f"Estimated minimum: {count / rate / 3600:,.2f} hours.")
    if count > 10000 and input("Type SCAN to start: ").strip() != "SCAN":
        return False
    if priority:
        print("Checking priority ports across the target first.")
    print(f"Scanning now. Writing matches to {output}.", flush=True)
    scanner.scan(jobs(), output, 2, rate, 16, minecraft_only=True, total=count)
    print(f"Minecraft results saved to {output}.")
    return True


def masscan_candidates(lines, network, ports):
    candidates = set()
    allowed_ports = set(ports)
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[:2] != ["open", "tcp"]:
            continue
        try:
            port = int(fields[2])
            ip = ipaddress.IPv4Address(fields[3])
        except ValueError:
            continue
        if ip in network and port in allowed_ports:
            candidates.add((str(ip), port, str(ip)))
    return sorted(candidates)


def scan_masscan(network, ports, output, rate, qubo_jar=None):
    if not sys.platform.startswith("linux"):
        raise ValueError("The Masscan backend requires Linux. Use guided mode without --masscan on Windows.")
    binary = shutil.which("masscan")
    if not binary:
        raise ValueError("Install Masscan before enabling --masscan.")
    if qubo_jar is not None and (not qubo_jar.is_file() or not shutil.which("java")):
        raise ValueError("--qubo-jar requires a QuboScanner JAR and JDK 21 on PATH.")
    count = network.num_addresses * len(ports)
    print(f"Masscan: {count:,} TCP probes at {rate}/s, about {count / rate / 60:,.1f} minutes "
          "before Minecraft checks.")
    if input("Type SCAN to start at this rate: ").strip() != "SCAN":
        return False
    with TemporaryDirectory() as directory:
        listing = Path(directory) / "open-ports.txt"
        command = [binary, str(network), "-p", display_ports(ports), "--rate", str(rate),
                   "-oL", str(listing)]
        effective = subprocess.run(command + ["--echo"], check=True, capture_output=True,
                                   text=True, timeout=15, cwd=directory)
        settings = {}
        for line in effective.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                settings.setdefault(key.strip(), []).append(value.strip())
        ranges = [ipaddress.IPv4Network(value) for value in settings.get("range", [])]
        configured_ports = settings.get("ports", [])
        if (ranges != [network] or len(configured_ports) != 1
                or set(parse_ports(configured_ports[0])) != set(ports)):
            raise ValueError("Masscan's effective targets or ports do not match the approved scope.")
        privileged = command if os.geteuid() == 0 else ["sudo", "--", *command]
        subprocess.run(privileged, check=True, cwd=directory)
        with listing.open(encoding="utf-8") as file:
            candidates = masscan_candidates(file, network, ports)

    print(f"Masscan found {len(candidates):,} open TCP candidates. Checking Minecraft Java status.")
    if qubo_jar is not None and candidates:
        scan_qubo(candidates, qubo_jar, output)
    else:
        scanner.scan(candidates, output, 2, 10, 16, minecraft_only=True, total=len(candidates))
    print(f"Minecraft results saved to {output}.")
    return True


def scan_qubo(candidates, jar, output):
    source = Path(__file__).with_name("QuboProbe.java")
    with TemporaryDirectory() as directory:
        endpoints = Path(directory) / "endpoints.tsv"
        endpoints.write_text("".join(f"{ip}\t{port}\n" for ip, port, _ in candidates), encoding="ascii")
        command = ["java", "--class-path", str(jar.resolve()), str(source), str(endpoints)]
        with output.open("x", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=scanner.FIELDS)
            writer.writeheader()
            file.flush()
            with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding="utf-8") as process:
                try:
                    for line in process.stdout:
                        ip, port, version, players, motd = line.rstrip("\r\n").split("\t")
                        version, motd = (base64.b64decode(value).decode("utf-8") for value in (version, motd))
                        print(f"{ip}:{port} Minecraft Java {version}", flush=True)
                        writer.writerow(dict(ip=ip, port=port, hostname=ip, service="Minecraft Java",
                                             version=csv_text(version), players=players, motd=csv_text(motd),
                                             observation="Public status response; access controls unverified"))
                        file.flush()
                except BaseException:
                    process.terminate()
                    raise
                if process.wait():
                    raise ValueError("The Qubo status checker failed. Check the JDK and JAR.")


def csv_text(value):
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def guided(args):
    rate = getattr(args, "masscan_rate", None)
    qubo_jar = getattr(args, "qubo_jar", None)
    use_masscan = getattr(args, "masscan", False) or (
        not getattr(args, "tcp", False) and sys.platform.startswith("linux") and shutil.which("masscan")
    )
    if not use_masscan and (rate is not None or qubo_jar is not None):
        raise ValueError("--masscan-rate and --qubo-jar require Masscan mode.")
    target = input("Approved IPv4 address or CIDR (Enter to exit): ").strip()
    if not target:
        return
    network = audit_network(target)
    if "/" not in target:
        block = ipaddress.IPv4Network(f"{target}/24", strict=False)
        print(f"Containing /24: {block} ({block.network_address}-{block.broadcast_address}).")
        if input("Use this /24 if the owner approved the entire block? [y/N]: "
                 ).strip().lower() == "y":
            network = block
    while True:
        value = input("Approved TCP ports (legacy, a list/range, or Enter for 1-65535): ").strip() or "1-65535"
        try:
            ports = parse_ports(value)
        except argparse.ArgumentTypeError as error:
            print(error)
        else:
            break
    if not confirm_scope([network], ports):
        return
    username = ""
    version = ""
    if input("Did the owner also approve bot login tests on these ports? [y/N]: "
             ).strip().lower() == "y":
        username = f"Audit_{secrets.token_hex(4)}"
        print(f"Offline test username: {username}")
        version = input("Minecraft client version [auto]: ").strip() or "auto"
    stamp = f"{datetime.now():%Y%m%d-%H%M%S-%f}"
    output = Path(f"audit-{stamp}.csv")
    if use_masscan:
        completed = scan_masscan(network, ports, output, rate or 1000, qubo_jar)
    else:
        completed = scan_targets([network], ports, output, rate=10)
    if completed and username:
        test_matches(output, Path(f"joins-{stamp}.csv"), username, version)


def test_username(value):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", value):
        raise ValueError("Enter the test username approved by the owner.")
    return value


def bot_command(ip, port, username, version):
    bot = Path(__file__).with_name("audit-bot") / "join.cjs"
    return ["node", str(bot), ip, str(port), username, version]


def test_matches(scan_output, join_output, username, version):
    with scan_output.open(encoding="utf-8-sig", newline="") as source, \
            join_output.open("x", encoding="utf-8-sig", newline="") as destination:
        writer = csv.writer(destination)
        writer.writerow(("ip", "port", "outcome", "detail"))
        for row in csv.DictReader(source):
            if row["service"] != "Minecraft Java":
                continue
            ip, port = row["ip"], row["port"]
            try:
                result = subprocess.run(bot_command(ip, port, username, version), timeout=20,
                                        capture_output=True, text=True, encoding="utf-8",
                                        errors="replace")
            except subprocess.TimeoutExpired:
                outcome, detail = "INCONCLUSIVE", "Bot process timed out."
            else:
                outcome = {0: "JOINED", 2: "REJECTED"}.get(result.returncode, "INCONCLUSIVE")
                detail = (result.stdout.strip() or result.stderr.strip())[:500]
            if detail.lstrip().startswith(("=", "+", "-", "@")):
                detail = "'" + detail
            print(f"{ip}:{port} {outcome}")
            writer.writerow((ip, port, outcome, detail))
            destination.flush()
    print(f"Bot results saved to {join_output}.")


def join(args):
    ip = str(ipaddress.IPv4Address(args.ip))
    if not 1 <= args.port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if input(f"Confirm the owner approved a bot login test on {ip}:{args.port} [y/N]: "
             ).strip().lower() != "y":
        return
    result = subprocess.run(bot_command(ip, args.port, test_username(args.username), args.version),
                            timeout=20)
    raise SystemExit(result.returncode)


def masscan_rate(value):
    try:
        rate = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Enter a whole number of packets per second.") from None
    if not 1 <= rate <= 100000:
        raise argparse.ArgumentTypeError("Masscan rate must be between 1 and 100000 packets per second.")
    return rate


def main():
    parser = argparse.ArgumentParser(description="Audit approved Minecraft Java endpoints.")
    parser.set_defaults(run=guided)
    commands = parser.add_subparsers(dest="command")
    guided_parser = commands.add_parser("guided", help="Scan an approved IP or CIDR and optionally test joins")
    backend = guided_parser.add_mutually_exclusive_group()
    backend.add_argument("--masscan", action="store_true", help="Require Masscan for TCP discovery on Linux")
    backend.add_argument("--tcp", action="store_true", help="Use the built-in TCP scanner")
    guided_parser.add_argument("--qubo-jar", type=Path, help="Use QuboScanner's mcping library on Masscan candidates")
    guided_parser.add_argument("--masscan-rate", type=masscan_rate, metavar="PPS",
                               help="Masscan packets per second (default: 1000)")
    scan = commands.add_parser("scan", help="Scan an explicit approved IPv4 address or CIDR")
    scan.add_argument("--target", action="append", required=True, help="IPv4 or CIDR; repeat as needed")
    scan.add_argument("--ports", type=parse_ports, default="1-65535", help="Port list, range, or legacy preset")
    scan.add_argument("--output", type=Path, default=Path("audit.csv"))
    scan.add_argument("--rate", type=int, choices=range(1, 26), default=10, metavar="1-25")
    scan.set_defaults(run=audit)
    bot = commands.add_parser("join", help="Try one direct join using an owner-approved offline test name")
    bot.add_argument("ip")
    bot.add_argument("port", type=int)
    bot.add_argument("--username", required=True)
    bot.add_argument("--version", default="auto", help="Minecraft client version (default: auto)")
    bot.set_defaults(run=join)
    args = parser.parse_args()
    try:
        args.run(args)
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted. Previously written CSV rows are kept.\n")
    except (OSError, EOFError, ValueError, KeyError, argparse.ArgumentTypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Audit failed: {error}\n")


if __name__ == "__main__":
    main()
