# Mitigata

Mitigata 0.3.0 is an evidence-first security assessment engine for explicitly authorized local labs and private IPv4 networks. Seven specialist roles—Recon, Web, Binary, Correlator, Falsifier, Code and Reporter—share a durable SQLite blackboard, exchange typed handoffs and verify findings against captured evidence.

The repository includes the Python backend, bundled HTML/CSS/JavaScript dashboard, runtime check data, generic configuration templates, Docker deployment files and reusable tests. FastAPI serves the frontend; no Node.js build is needed. The demo and deterministic checks require no LLM key. Claude assistance, browser checks and external discovery tools are optional.

## Quick start

Use Python **3.12 or 3.13**. From the repository root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\python.exe -m mitigata serve --demo --output runtime/live
```

Open **http://127.0.0.1:8765/** and enter the token in `runtime/live/operator-token.txt`. Select **+ new run** to create a fresh loopback lab. The dashboard displays run state, agent activity, handoffs, findings, verification controls, an access graph and downloadable reports.

For subsequent launches, run `scripts/start.ps1`. On Linux/macOS, use `.venv/bin/python` instead of the Windows Python path, or run `sh scripts/start.sh` to set up and start the demo. Change ports with `scripts/start.ps1 -Port 8769` or `sh scripts/start.sh 8769`.

## Command-line demo and reports

```powershell
.\.venv\Scripts\python.exe -m mitigata demo
.\.venv\Scripts\python.exe -m mitigata demo --seed 73 --layout json
.\.venv\Scripts\python.exe -m mitigata demo --no-flag --output runtime/negative
.\.venv\Scripts\python.exe -m mitigata demo --fixed --output runtime/fixed
```

Each demo creates a generated loopback lab in a separate process. The engine discovers services, follows references, inspects an artifact without executing it, correlates evidence and attempts to retrieve a protected code. A separate evaluator scores the completed run. These fixtures validate supported behavior; they do not establish coverage of arbitrary applications.

The output directory contains `state.sqlite3`, private `evidence/<run-id>/` and `reports/<run-id>/report.html` plus `report.json`. Demo reports also include `evaluation.json` when evaluation completes.

Reports redact intermediate credentials and evidence previews, but deliberately show captured codes to the authenticated operator. Reports, bundles, raw evidence, databases and captures can therefore contain secrets and must stay in an operator-controlled directory. Downloadable bundles exclude raw captures. A separate exact-code export is available with:

```powershell
.\.venv\Scripts\python.exe -m mitigata flags RUN_ID --root runtime/demo --output runtime/protected-flags.json --include-secrets
```

## Configure an assessment

The scope templates in `examples/` use illustrative addresses and **are disabled and unauthorized by default**. Copy one into the ignored `engagements/` directory, configure actual addresses, ports, paths and budgets, supply an authorization reference, then set `enabled: true` and `authorized: true`.

- `local.scope.yaml`: loopback services.
- `network.discovery.yaml`: bounded private-network discovery.
- `network.assessment.yaml`: private-network HTTP and Redis INFO checks, with credential use disabled.
- `network.confined.yaml`: discovery through the Linux confinement supervisor.
- `ai.assessment.yaml`: native investigation with required Claude assistance.
- `ai.confined.yaml`: Linux-confined AI assessment with a separate model gateway, browser support and external tools.

AI templates permit additional actions, including credential and injection checks. Review their action/check allowlists against your authorization before enabling them. Templates do not grant permission to assess the example address.

```powershell
New-Item -ItemType Directory -Force engagements | Out-Null
Copy-Item examples/local.scope.yaml engagements/local.yaml
# Edit engagements/local.yaml before continuing.
.\.venv\Scripts\python.exe -m mitigata dry-run engagements/local.yaml
.\.venv\Scripts\python.exe -m mitigata preflight engagements/local.yaml
.\.venv\Scripts\python.exe -m mitigata run engagements/local.yaml --output runtime/assessment
```

`dry-run` validates scope without DNS or network connections. `preflight` also reads routing state without target probes. To start a configured run with its live dashboard:

```powershell
.\.venv\Scripts\python.exe -m mitigata serve --manifest engagements/local.yaml --output runtime/assessment-live --port 8767
```

Open **http://127.0.0.1:8767/** and use `runtime/assessment-live/operator-token.txt`.

Scopes pin numeric destinations, hostname bindings, ports, paths and allowed actions. Discovered references cannot expand scope. Connections preserve HTTP authority and TLS hostname verification while using approved numeric addresses; redirects are checked again. Request, time, rate, size and authentication budgets bound work. Reports record untested scope when runs end early.

Resume interrupted work after leases expire with the identical manifest:

```powershell
.\.venv\Scripts\python.exe -m mitigata run engagements/local.yaml --output runtime/assessment --resume RUN_ID
```

State and authentication counts survive resume. After a crash, an uncertain action can be repeated. Cancellation stops queued work and closes active broker sockets; partial runs still produce reports.

## Optional AI and tools

Copy `.env.example` to `.env.local` and configure `ANTHROPIC_API_KEY` for native Claude assistance. Gateway deployments also require a random private `MITIGATA_AI_GATEWAY_TOKEN`. Generate one locally with:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

The application reads supported settings from `.env.local`. Configure the model, shared dollar budget, call limits and context limits in the manifest's `ai` section. Check configuration and tools without target probes using `mitigata doctor engagements/ai.yaml`. Required AI configurations fail readiness checks when credentials are missing.

For native browser checks, install Chromium using `python -m playwright install chromium` in the project environment, or set `MITIGATA_CHROME_PATH`. Install other optional native tools separately. The Linux amd64 Docker image includes Chromium, nmap, static binary tools and checksum-verified ffuf, katana and nuclei releases. Live tool execution is restricted by scope and execution profile; unavailable capabilities are reported explicitly.

## Docker

```powershell
docker compose up --build -d
```

Open **http://127.0.0.1:8766/** and use `runtime/container/operator-token.txt`. The default engine runs as non-root with a read-only filesystem on an internal network. A separate gateway exposes the dashboard on loopback. The observer shares the engine network namespace and adds `NET_RAW` for capture. Start an assessment after the observer is ready.

Flush capture with `docker compose stop observer`; stop the deployment with `docker compose down`. State remains under the ignored `runtime/` directory. On Windows, `scripts/validate-container.ps1` automates a demo and independent capture analysis. For manual analysis use `mitigata observe --help`. Measurements need a complete run window, source addresses and zero capture drops; incomplete data is inconclusive, and missing data is reported as unavailable.

For a private-network assessment, configure and authorize a copy of `examples/network.confined.yaml` at `engagements/confined.yaml`, then run:

```powershell
docker compose -f compose.assessment.yaml up --build --abort-on-container-exit --exit-code-from assessment-runner
```

The supervisor installs a Linux kernel egress policy before dropping worker privileges. Output goes to `runtime/assessment-contained` and `runtime/assessment-capture`. Set `MITIGATA_SCOPE_FILE` to select a different manifest.

For the AI dashboard, configure `.env.local` and an authorized copy of `examples/ai.confined.yaml` at `engagements/ai.confined.yaml`, then run:

```powershell
docker compose --env-file .env.local -p mitigata-ai -f compose.ai.yaml up --build -d
```

Open **http://127.0.0.1:8768/** and use `runtime/ai-linux/operator-token.txt`. The model gateway holds the provider key; the engine receives the gateway capability. The Compose network uses `172.30.251.0/24`; adjust both network configuration and the manifest gateway address if that subnet conflicts with your environment. Stop it with:

```powershell
docker compose --env-file .env.local -p mitigata-ai -f compose.ai.yaml down
```

## Checks and API

The default pack contains **21 check recipes** across web, network and binary surfaces. Capabilities include disclosure checks, artifact credential recovery, bounded authentication/injection checks, forwarding-header controls and reviewed text-protocol interactions. Findings require their registered proof conditions; reflection, missing hardening or scanner candidates alone do not establish compromise. Downloaded binaries are never executed.

Add a recipe using an existing registered primitive:

```powershell
.\.venv\Scripts\python.exe -m mitigata run engagements/local.yaml --checks examples/checks.openapi.yaml
```

Unknown primitives and arbitrary shell commands are rejected. New verification semantics require implementation of a reviewed primitive.

All `/api/*` endpoints require `Authorization: Bearer <operator token>`. Unknown Host values and cross-origin browser requests are rejected. Health and dashboard assets are public locally. The frontend uses bundled assets without third-party JavaScript, fonts or analytics.

Main routes include `POST /api/runs`, `POST /api/demo`, `GET /api/runs`, `GET /api/runs/{id}`, `POST /api/runs/{id}/cancel` and `GET /api/runs/{id}/events` (SSE with `Last-Event-ID`). Per-run routes also expose findings, handoffs, briefings, verifications, graph data, checks, reports, bundles and evidence. Exact code export uses `POST /api/runs/{id}/flags/export`. The authenticated alias `GET /targets/{id}/findings` is also available.

## Development and validation

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check mitigata tests
.\.venv\Scripts\python.exe -m mitigata benchmark --output runtime/benchmark
```

Tests cover generated and separately authored local fixtures, scope enforcement, DNS pinning, TLS identity, evidence integrity, redaction, durable work, cancellation, API access and verification. GitHub Actions runs tests and lint on Windows/Linux with Python 3.12/3.13, plus a Docker network-confinement integration on Linux. Benchmark metrics describe the supported fixture family.

## Repository privacy

Public commits contain application source, frontend assets, runtime check data, generic examples, deployment configuration and reusable tests. `.gitignore` keeps non-README documents, private engagement configurations, pentesting-only fixtures/helpers, evidence, reports, captures, databases, environment files and generated deliverables local. Text wordlists in `mitigata/data/` are required runtime inputs and remain included. `.dockerignore` restricts the build context to source and test inputs.

Keep target-specific manifests in `engagements/` and run output under `runtime/` or `output/`. Review staged content before publishing: ignored files can still be forced into Git, and ignore rules do not remove existing history.
