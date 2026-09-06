<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX User Scanner worker

This directory contains the isolated active-OSINT worker used by the PARA11AX terminal `user-scanner` command. It intentionally sits outside the passive Evidence v2 provider pipeline.

Local run:

```bash
cd workers/user-scanner
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export USER_SCANNER_WORKER_TOKEN='replace-me'
python server.py
```

Then configure the PARA11AX gateway:

```bash
PARA11AX_USER_SCANNER_URL=http://127.0.0.1:8765/scan
PARA11AX_USER_SCANNER_TOKEN=replace-me
```

For hosted use, create a separate Vercel project with `workers/user-scanner` as its Root Directory. Set `USER_SCANNER_WORKER_TOKEN` in that worker project and set the main PARA11AX project's `PARA11AX_USER_SCANNER_URL` to the deployed `/scan` endpoint plus the matching `PARA11AX_USER_SCANNER_TOKEN`.

The gateway does not accept worker URLs, proxies, concurrency values, timeouts, arbitrary module paths, or loud-module toggles from terminal users. Cross-scan is opt-in and fixed to depth 1. NSFW modules are excluded unless the analyst explicitly adds `--include-nsfw`.

Terminal examples:

```text
user-scanner username kaifcodec
user-scanner username kaifcodec --module github
user-scanner username kaifcodec --category dev --cross-scan
user-scanner email analyst@example.com
```

Aliases: `osint`, `identity`.

## Platform boundary

User Scanner is one specialist operator surface in the unified PARA11AX shell. Native Shodan and GreyNoise Project Swarm are separate gateway handlers with separate credentials, upstream destinations, request grammars, bounds, and vendor semantics. This worker does not proxy, call, share credentials with, or provide fallback for either service.

GreyNoise Project Swarm commands are `swarm search`, `swarm get`, `swarm unique`, `swarm timeseries`, and `swarm export`; they are handled by the main gateway's fixed `/api/para11ax/swarm` route, not by this worker. Likewise, Shodan commands use `/api/para11ax/shodan` and never pass through this worker.

User Scanner results remain contextual active-OSINT operator material rather than automatic Evidence v2. Compatible results may be explicitly captured into Investigation Workspace with `investigation capture operator`, preserving the operator-context authority label. The same authority rule applies to compatible Shodan and GreyNoise Swarm read results; Swarm PCAP/raw exports remain explicit browser downloads outside automatic capture.

See [`../../docs/SHELL.md`](../../docs/SHELL.md), [`../../docs/GREYNOISE-SWARM.md`](../../docs/GREYNOISE-SWARM.md), and [`../../docs/SHODAN-SHELL.md`](../../docs/SHODAN-SHELL.md).

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>