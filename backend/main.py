"""
FastAPI application entrypoint for the Memory Forensics Platform.

Run locally with:
    uvicorn main:app --reload --port 8000
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db.database import init_db
from api.routes import router
from api.rate_limit import RateLimitMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Memory Forensics-Based Suspicious Process Detection and Investigation Platform",
    version="1.0.0",
    description="API for uploading, analyzing, and investigating memory forensic images.",
    lifespan=lifespan,
)

# Allow the local React dev server to call this API during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic request throttling -- see api/rate_limit.py docstring for scope
# rationale (in-memory, single-process; sufficient for this project's
# documented single-user academic deployment, not a multi-worker production
# service).
app.add_middleware(RateLimitMiddleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Ensure every error response has a consistent {"detail": "..."} shape (TC-API-06)."""
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/health")
def health_check():
    return {"status": "ok"}


app.include_router(router, prefix="/api")
