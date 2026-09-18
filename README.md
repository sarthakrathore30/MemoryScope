# Memory Forensics-Based Suspicious Process Detection and Investigation Platform

An automated memory forensics platform that ingests memory dump images, extracts
processes/modules/network artifacts via [Volatility 3](https://github.com/volatilityfoundation/volatility3),
detects hidden and suspicious processes, scans for known malware signatures with
[YARA](https://virustotal.github.io/yara/), and generates structured investigation
reports (PDF/JSON) through a web dashboard.

See `PROJECT_PROPOSAL.docx`, `SOFTWARE_REQUIREMENTS_SPECIFICATION.docx`,
`SYSTEM_ARCHITECTURE_DESIGN_DOCUMENT.docx`, `DATABASE_SCHEMA_DOCUMENT.docx`,
`PROJECT_PLAN.docx`, and `TESTING_PLAN.docx` for the full design documentation
this implementation follows.

## Architecture

```
React dashboard (frontend/)
        │  REST/JSON over HTTP
        ▼
FastAPI backend (backend/)
  ├── acquisition/   upload handling, format validation, OS profile detection
  ├── analysis/      Volatility 3 wrapper (pslist, psscan, pstree, dlllist, netscan)
  ├── detection/     hidden-process cross-view, YARA scanning, heuristics, IOC extraction
  ├── reporting/     PDF/JSON report generation
  ├── api/           FastAPI routes + pipeline orchestration
  └── db/            SQLAlchemy models (SQLite dev / PostgreSQL-ready)
```

## Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- ~2 GB free disk space (Volatility 3 + symbol tables)

## Backend setup

```bash
cd backend
python3 -m venv ../venv
../venv/bin/pip install -r requirements.txt
```

Run the API server:

```bash
../venv/bin/uvicorn main:app --reload --port 8000
```

The API is now at `http://localhost:8000/api`, interactive docs at
`http://localhost:8000/docs`, health check at `http://localhost:8000/health`.

On first run, `main.py`'s startup hook creates `backend/memforensics.db`
(SQLite) with all 7 tables automatically — no manual migration needed.

### Running the backend test suite

```bash
cd backend
../venv/bin/python -m pytest tests/ -v
```

40 tests cover the Acquisition, Analysis, Detection, API, and end-to-end
scenario layers (mapped to `TESTING_PLAN.docx` test case IDs — TC-AC-\*,
TC-AN-\*, TC-DT-\*, TC-API-\*, and E2E-01 through E2E-04). Volatility3/YARA
calls are mocked at the subprocess/library boundary so the suite runs in
under 2 seconds without needing a real memory image.

## Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The dev server is pre-configured (via CORS in
`backend/main.py`) to talk to the backend at `http://localhost:8000/api`. To
point at a different backend URL, copy `.env.example` to `.env` and set
`VITE_API_BASE_URL`.

Build a production bundle with `npm run build` (outputs to `frontend/dist/`).

## Docker (alternative to manual setup)

A `docker-compose.yml` at the project root builds and runs both services
together, per the deployment architecture in
`SYSTEM_ARCHITECTURE_DESIGN_DOCUMENT.docx` (section 7):

```bash
docker compose up --build
```

- Backend API: `http://localhost:8000/api` (docs at `/docs`)
- Frontend: `http://localhost:5173`

The SQLite database, uploaded images, and generated reports persist in
named Docker volumes across restarts. `yara_rules/` is bind-mounted from
the host, so rules can be added or edited live without rebuilding the
image (FR-14).

**Note:** these Docker files were authored without access to a Docker
daemon in the development environment, so they have not been build-tested
end-to-end. The Dockerfiles parse correctly and follow standard, verified
patterns (multi-stage Vite build served via nginx with SPA fallback
routing; pinned dependencies from `requirements-lock.txt` for the backend),
but please run `docker compose up --build` yourself and report any issues
before relying on this for a real deployment or demo.

## Using the platform end-to-end

1. Open the dashboard, enter a case name, and click **Open new case**.
2. Drag a memory image (`.raw`, `.mem`, `.dmp`, `.vmem`, `.img`, `.bin`, `.lime`)
   onto the upload panel, or click to browse.
3. Once uploaded and validated, click **Run analysis**. This runs the full
   Acquisition → Analysis → Detection → Storage pipeline.
4. Review results across the **Processes**, **Process tree**, **Network**,
   and **IOCs** tabs.
5. Export findings from the **Report** tab as PDF or JSON.

### Getting real sample memory images

This repository does not include sample memory images (they're large binary
files). For testing against real data, the Volatility Foundation publishes
public sample images and required symbol tables — search "Volatility 3
sample memory images" for current download links, since these move over
time. Volatility 3 will also prompt to auto-download the correct Windows
symbol table (PDB) for a given image on first analysis, provided the machine
running the backend has normal internet access (unlike this project's
original sandboxed development environment, which could not reach
`downloads.volatilityfoundation.org`).

## YARA rules

Rules live in `yara_rules/*.yar` and are compiled fresh on every analysis —
add or edit rules there without touching any code (FR-14). Scanning runs
directly against live process memory inside the image via Volatility 3's own
`windows.vadyarascan.VadYaraScan` / `linux.vmayarascan.VmaYaraScan` plugins
(no separate memory-dump-and-scan step needed). A small illustrative sample
rule set (`sample_rules.yar`) is included for demonstration; replace or
extend it with rules from sources like the
[Yara-Rules](https://github.com/Yara-Rules/rules) community repository for
more realistic detection coverage. A syntax error in any rule file is caught
and reported clearly before analysis runs, rather than surfacing as an
opaque Volatility failure.

## Known limitations / scope notes

- **Rate limiting is in-memory, single-process.** A lightweight sliding-
  window limiter (120 req/min general, 10 req/min for upload/analyze)
  protects against trivial flooding, appropriate for this project's
  documented single-user academic deployment. It will not work correctly
  across multiple worker processes or horizontally-scaled deployments
  (each process has its own independent counters) -- a real multi-user
  production deployment should replace this with a shared store (Redis).
  See `backend/api/rate_limit.py`.
- **Upload signature validation is necessarily partial.** Raw physical
  memory dumps (`.raw`, `.vmem`, `.img`, `.bin`, `.mem`) have no defined
  file header at all — they're a flat byte stream starting with whatever
  RAM happened to contain, so there's nothing to check a magic-byte
  signature against for those extensions. Only `.dmp` (Windows crash dump:
  `PAGEDUMP`/`PAGEDU64` header, high confidence) and `.lime` (LiME format:
  `0x4c694d45` magic, included in good faith but not verified against a
  real captured `.lime` file in this environment) have an actual signature
  check. See `acquisition/validators.py`.
- **FR-8 (suspicious heuristics)**: all three SRS examples are addressed.
  Lineage-based checks (unusual parent, orphaned/self-parented/spoofed-PPID
  processes) and anomalous-memory-region detection (via Volatility's
  `malfind` plugin — private, executable memory not backed by any file on
  disk, the classic code-injection/process-hollowing signature) are fully
  implemented. **Unsigned binaries** are addressed via a practical proxy,
  not true Authenticode verification (no Volatility plugin exposes
  signature checking — it would require dumping each PE from memory and
  parsing its certificate table, a much larger undertaking): well-known
  system processes (svchost.exe, lsass.exe, etc.) are flagged if their
  actual executable path doesn't match the expected system directory (e.g.
  a fake `svchost.exe` launched from a Temp folder). This catches the
  common "name malware after a trusted process" trick but is not equivalent
  to real signature verification — a genuinely unsigned/tampered binary
  sitting in the correct directory would not be caught. See
  `check_masquerading_path()` in `backend/detection/heuristics.py`.
- **Live memory acquisition** from a running system is explicitly out of
  scope (per the SRS) — the system only analyzes pre-captured dump files.
- **Single-user, academic-scale deployment** — no authentication/authorization
  layer, and no testing under concurrent multi-analyst load.
- **ML-based risk scoring** (`risk_score` column) is reserved but not
  implemented — a documented future extension point per the architecture doc.

## Project structure

```
memory-forensics-platform/
├── backend/
│   ├── acquisition/       upload, validation, OS profile detection
│   ├── analysis/          Volatility3 wrapper
│   ├── detection/         hidden-process, heuristics, YARA, IOC extraction
│   ├── reporting/         PDF/JSON report generation
│   ├── api/               FastAPI routes, pipeline orchestration, schemas
│   ├── db/                SQLAlchemy models + session management
│   ├── tests/             86 tests (unit + integration + E2E)
│   ├── main.py            FastAPI app entrypoint
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/               React (Vite) dashboard
│   ├── Dockerfile
│   └── nginx.conf         SPA fallback routing for the Docker build
├── docker-compose.yml
├── yara_rules/             YARA rule files (admin-editable, no code changes needed)
├── uploads/                uploaded memory images (gitignored)
├── reports/                generated PDF/JSON reports (gitignored)
└── *.docx                  project design documentation
```
