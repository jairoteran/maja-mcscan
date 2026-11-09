# Maja MCScan

Maja MCScan finds Minecraft Java servers on authorized IPv4 addresses and optionally tests direct access with an offline Minecraft client.

## Setup

The built-in scanner needs Python 3.10 or newer. QuboScanner and Java are not required. Masscan is required only for the optional Linux mode below. Install Node.js 24 and npm if you want to run the join bot, then run:

```sh
npm ci --prefix audit-bot
```

## Guided scan

```sh
python minecraft_audit.py
```

Enter an IPv4 address or CIDR from `/24` to `/32`. For a single IP, the tool shows the containing `/24` and lets you choose whether to use it.

Enter a port, a range, a comma-separated list, or `legacy` for the 299-port preset. Press Enter for all TCP ports from 1 through 65535. Confirm the authorized scope before scanning. The built-in scanner uses up to 10 connection attempts per second in guided mode.

## Masscan on Linux

Install Masscan and make it available on your PATH. Masscan needs privileges to send raw packets. The Python process runs normally and prompts through sudo for the Masscan step when needed.

```sh
python3 minecraft_audit.py guided --masscan
```

Masscan discovers open TCP ports first. The tool then checks those candidates for Minecraft Java. The default is 1,000 packets per second. Use `--masscan-rate PPS` to set the packet rate within the limits of your environment. The estimate shown before confirmation covers the TCP sweep. Status checks and join tests take additional time.

## Reports

- `audit-*.csv` lists endpoints that answered a Minecraft Java status request.
- `joins-*.csv` records optional join tests. Enable this option for authorized login testing. The bot generates one offline test name per run.

`JOINED` confirms direct access for that test client. `REJECTED` records a server rejection. `INCONCLUSIVE` covers errors and timeouts. Correlate the tested port with the proxy configuration to determine whether it belongs to an internal game server.
