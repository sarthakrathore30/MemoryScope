# MemoryScope

Automated Memory Forensics and Suspicious Process Detection Platform

MemoryScope is an automated memory forensics platform that analyzes memory dump files using Volatility 3 and YARA. It detects hidden and suspicious processes, extracts network artifacts and Indicators of Compromise (IOCs), and generates structured investigation reports in PDF and JSON format through a web dashboard.

## Architecture

```text
React Dashboard (frontend/)
        │
        │ REST/JSON over HTTP
        ▼
FastAPI Backend (backend/)
├── acquisition/   Upload handling, file validation, OS detection
├── analysis/      Volatility 3 plugin execution
├── detection/     Hidden process detection, YARA scanning, IOC extraction
├── reporting/     PDF and JSON report generation
├── api/           FastAPI routes and analysis pipeline
└── db/            SQLAlchemy models and database
```

## Features

- Memory dump analysis using Volatility 3.
- Hidden and suspicious process detection.
- YARA-based malware signature scanning.
- Process tree and DLL analysis.
- Network artifact extraction.
- Indicator of Compromise (IOC) detection.
- Interactive investigation dashboard.
- PDF and JSON report generation.

## Tech Stack

### Frontend

- React.js, Vite, Tailwind CSS, Axios

### Backend

- FastAPI, Python, Volatility 3, YARA-Python, SQLAlchemy, ReportLab

### Database

- SQLite, PostgreSQL (supported)

## Prerequisites

-Python 3.10 or later, Node.js 18 or later, npm

## Backend Setup

# Windows

```bash
python -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
cd backend
pip install -r requirements.txt
uvicorn main:app --port 8000
```

The backend runs at:

- API: `http://localhost:8000/api`
- Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at:

`http://localhost:5173`

## Docker Setup

Run both frontend and backend using Docker Compose.

```bash
docker compose up --build
```

## Using MemoryScope

1. Open the web dashboard.
2. Create a new investigation case.
3. Upload a supported memory dump file.
4. Run the analysis pipeline.
5. Review processes, process tree, network artifacts, and IOCs.
6. Export the investigation report in PDF or JSON format.

## Supported Memory Dump Formats

- `.raw`
- `.mem`
- `.dmp`
- `.vmem`
- `.img`
- `.bin`
- `.lime`

## YARA Rules

YARA rules are stored in the `yara_rules/` directory. Add or update `.yar` files to scan memory images with custom malware signatures during analysis.

## Project Structure

```text
MemoryScope/
├── backend/
│   ├── acquisition/
│   ├── analysis/
│   ├── detection/
│   ├── reporting/
│   ├── api/
│   ├── db/
│   ├── tests/
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   ├── public/
│   ├── Dockerfile
│   └── nginx.conf
├── yara_rules/
├── uploads/
├── reports/
├── docker-compose.yml
└── README.md
```

## Testing

Run the backend test suite.

```bash
cd backend
pytest tests -v
```

## Limitations

- Supports analysis of pre-captured memory dump files only.
- Live memory acquisition is not supported.
- Designed for single-user academic deployment.
- Risk scoring is reserved for future machine learning integration.

## Future Enhancements

- Live memory acquisition support.
- Machine learning-based threat scoring.
- Multi-user authentication and role management.
- Additional Volatility plugin integration.

## Author

MemoryScope is developed as a cybersecurity project focused on automated memory forensics and threat investigation.
