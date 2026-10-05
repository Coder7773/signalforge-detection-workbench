# SignalForge

**A local-first detection engineering and incident triage workbench.** Ingest normalized endpoint and identity events, correlate them with transparent detection rules, and investigate the resulting alerts in a small web dashboard.

SignalForge is designed as a portfolio lab: clone it, run it locally, inspect the rules, then send the API your own authorized sample telemetry. It ships with synthetic data and does not execute commands or take action on endpoints.

## What it demonstrates

- Event validation and normalization at the API boundary, with timestamps stored in UTC.
- Correlation across events for repeated authentication failures.
- Local import for Windows Event XML, Linux SSH/sudo auth logs, and normalized JSONL.
- Four inspectable rules mapped to MITRE ATT&CK technique IDs.
- Idempotent alert creation using stable fingerprints.
- Alert triage states: new, investigating, resolved, and false positive.
- A browser dashboard for metrics, alerts, event review, and evidence inspection.
- Local persistence with SQLite and a dependency-free Python runtime.
- A hardened container setup: non-root user, read-only root filesystem, dropped Linux capabilities, and a persistent data volume.

## Detection catalog

| Rule | Detection | Severity | ATT&CK |
|---|---|---:|---|
| `SF-AUTH-001` | Five or more failed logins for one account from one source within ten minutes | High | T1110 · Brute Force |
| `SF-WIN-001` | Encoded PowerShell or a Base64 decoding indicator in a process command line | High | T1059.001 · PowerShell |
| `SF-LNX-001` | File write to common cron, systemd, or SSH key persistence locations | Medium | T1053.003 · Cron |
| `SF-IAM-001` | Account change mentioning a privileged group | High | T1098 · Account Manipulation |

Rules are starter heuristics for synthetic lab events. Review and tune them before using other telemetry; they are not a substitute for a production detection program.

## Run locally

Runs on Windows, Linux, and macOS with Python 3.11 or later. There are no third-party Python packages to install.

```powershell
cd signalforge
py -3 app.py --demo
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). The app binds to localhost by default and stores its database at `data/signalforge.db`. Stop it with `Ctrl+C`.

On Linux or macOS, use `python3 app.py --demo` instead. Windows can run the tests with `py -3 -m unittest discover -s tests -v`; Linux and macOS can use `python3 -m unittest discover -s tests -v`.

To use another database path, set `SIGNALFORGE_DB` before starting the app. To start on another port, use `--port 8090`.

Run the 20 standard-library tests with `py -3 -m unittest discover -s tests -v` on Windows or `python3 -m unittest discover -s tests -v` on Linux/macOS. They cover detections, local log adapters and CLI setup, input validation, same-origin writes, cross-site rejection, security headers, API health, read-only behavior, and malformed JSON. GitHub Actions runs the suite on Windows, Linux, and macOS with Python 3.11–3.14.

## Run with Docker Compose

Requires Docker Engine with the Compose plugin.

```sh
docker compose up --build
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). Compose seeds a read-only demo and keeps its database in the named `signalforge-data` volume. For a writable lab, run `py -3 app.py --demo` (Windows) or `python3 app.py --demo` (Linux/macOS) directly; the native server accepts writes only from loopback. To stop Compose, press `Ctrl+C`; remove the container with `docker compose down`. Removing the volume is a separate action: `docker compose down -v`.

## Publish a free read-only demo

`render.yaml` is set up for a public Render web service on the free plan. It seeds only the bundled synthetic events and sets `SIGNALFORGE_READ_ONLY=true`, which disables event ingestion, demo reset, and alert-status updates on the public demo.

1. Push the contents of this folder to a GitHub repository (the `Dockerfile` and `render.yaml` should be at the repository root).
2. Sign in to Render and create a **Blueprint** from that repository.
3. Review the service settings and keep the compute plan at **Free**; do not add a paid database or persistent disk for this demo.
4. Wait for the health check to pass, then open the service's `onrender.com` URL.

Render's free web services sleep after 15 minutes without traffic and can take about a minute to wake. Their filesystem is ephemeral, so the local demo database resets after sleep, restart, or deploy; the bundled synthetic dataset is reloaded at startup. Free services have usage limits, so check the account's included bandwidth and instance hours and avoid adding paid resources. See [Render's current free-service limits](https://render.com/docs/free).

## Try the demo

The seeded records are synthetic. They include a five-attempt login burst, encoded PowerShell command-line telemetry, a cron-path file event, a privileged-group change, and routine logins. The PowerShell command is only data: SignalForge never runs it. The dashboard should show four alerts.

Use **Reload demo** in the dashboard to replace the local database with the bundled synthetic events. Or use the API:

```sh
curl -X POST http://127.0.0.1:8080/api/demo/reset \
  -H 'Content-Type: application/json' \
  -d '{"reset":true}'
```

Windows PowerShell equivalent:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/demo/reset `
  -ContentType 'application/json' -Body '{"reset":true}'
```

## Ingest authorized sample events

Send an event list to `POST /api/ingest`. `event_type` and `host` are required; timestamps are ISO 8601. Accepted optional fields include `user`, `src_ip`, `process`, `command_line`, `outcome`, `target_path`, and `details`.

```sh
curl -X POST http://127.0.0.1:8080/api/ingest \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"timestamp":"2026-10-05T10:00:00Z","event_type":"auth_failure","host":"lab-linux-01","user":"analyst","src_ip":"192.0.2.15","outcome":"failure"}]}'
```

The request limit is 1 MB and a batch can contain up to 5,000 events. The response reports validated, newly stored, and duplicate records. The API rejects invalid fields and does not fetch external threat feeds.

## Import local Windows and Linux logs

The importer writes into the same local SQLite database and runs the same detection rules as API ingestion. It accepts supported Windows Event XML records (including Sysmon process, network, file, registry, DNS events and Security logon/group-change events), Linux `auth.log` SSH success/failure and sudo records, or normalized JSONL. It reads local files only; `.evtx` is not read directly.

On Windows, export a bounded XML sample, then import it:

```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:Events /c:5000 > sysmon.xml
py -3 import_logs.py --format windows-xml .\sysmon.xml
```

Use `Security` instead of the Sysmon channel to import Windows sign-in and group-change events. On Linux:

```sh
python3 import_logs.py --format linux-auth /var/log/auth.log --timezone +05:30
```

Syslog timestamps do not include a year or timezone. The importer uses the current year and UTC unless `--timezone` is provided; confirm both assumptions against the source host before relying on alert times. Imports are capped at 50 MB and 5,000 records. Only supported event IDs and SSH/sudo line formats are mapped; unrecognized records are skipped. Use synthetic or authorized logs and avoid importing sensitive data into a public demo.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health and version |
| `GET` | `/api/overview` | Event and alert counts by status and severity |
| `GET` | `/api/alerts?status=new` | List alerts; filter by a triage status or `all` |
| `GET` | `/api/events` | Latest 200 normalized events |
| `POST` | `/api/ingest` | Validate, store, and analyze an event batch |
| `PATCH` | `/api/alerts/{id}` | Update an alert status |
| `POST` | `/api/demo/reset` | Replace the local data with the synthetic dataset; requires `{"reset":true}` |

## Example portfolio walkthrough

1. Start the service and show the seeded data and four alert types.
2. Open the brute-force alert and explain the ten-minute sliding correlation window and its evidence.
3. Mark one alert investigating, then resolve it; show the status metric update.
4. Ingest a short authorized lab event batch and explain how rule fingerprints avoid duplicate alerts.
5. Import a supported Windows XML or Linux auth log, then inspect its normalized events and resulting alert evidence.
6. Walk through `run_detections` in `app.py`, then discuss how authentication, retention, and production-grade source coverage would extend this lab.

## Repository layout

```text
signalforge/
├── app.py                    # HTTP API, SQLite persistence, validation, and detections
├── import_logs.py            # Local Windows XML, Linux auth, and JSONL import
├── compose.yaml              # Local container setup
├── Dockerfile                # Hardened Python image
├── data/demo_events.jsonl    # Synthetic demo telemetry
├── static/index.html         # Dashboard markup and styles
└── static/app.js             # Dashboard behavior
```

## GitHub

Source code: [Coder7773/signalforge-detection-workbench](https://github.com/Coder7773/signalforge-detection-workbench). The free read-only demo uses the included render.yaml Blueprint; deployment steps are in the section above.


## Security and scope

- The native server binds to `127.0.0.1` by default. A non-loopback bind is always read-only, even if `SIGNALFORGE_READ_ONLY=false` is set; writable API calls also require a loopback client and same-origin HTTP scheme. The Docker image and Compose demo are read-only.
- Writable mode has no user authentication and is limited to loopback. Use synthetic or otherwise authorized non-sensitive events. The app does not provide TLS termination or production retention controls.
- Detection runs over the local event store and is intended for a small lab dataset, not high-volume production telemetry.
- No exploit payloads, endpoint commands, persistence changes, or automated containment actions are performed.

## LinkedIn post draft

> I built **SignalForge**, a local-first detection engineering and incident triage workbench in Python. It imports supported Windows Event XML and Linux SSH/sudo logs, normalizes events, correlates repeated authentication failures, maps detections to MITRE ATT&CK, and gives analysts a dashboard to inspect evidence and manage alert status.
>
> The project runs with Python's standard library or Docker Compose and uses synthetic telemetry, so anyone can clone it and reproduce the demo. I focused on transparent rules, input validation, idempotent alerts, and a hardened container setup.
>
> The log import is deliberately limited to documented event IDs and auth.log patterns; broader source coverage and Sigma rule support are possible next steps. Feedback on the correlation logic and detection tuning is welcome.
>
> GitHub: [add your repository link] · Demo: [add a short screen recording]

Replace the links with your real repository and a recording after you publish and run the project. Describe only the features you have personally reviewed and can explain.

## License

MIT. See [LICENSE](LICENSE).

