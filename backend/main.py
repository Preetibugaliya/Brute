"""
FastAPI Backend - Brute Force Detection Tool
=============================================
Provides:
  - JWT Admin Authentication
  - Login Attempt Processing API
  - Real-time WebSocket log streaming
  - Dashboard Statistics API
  - Simulation endpoints
  - Log Export (CSV)
  - IP Blocking
"""

import csv
import io
import time
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional, AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
import aiofiles
import os

# Local modules
import detection_engine as engine
import simulator as sim

# ─────────────────────────────────────────────────────
# JWT & Auth Configuration
# ─────────────────────────────────────────────────────
SECRET_KEY = "bruteforce-detection-secret-key-2024-do-not-share"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# Demo admin credentials (in production, store hashed passwords in DB)
ADMIN_USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
        "role": "admin"
    }
}

# ─────────────────────────────────────────────────────
# WebSocket Connection Manager
# ─────────────────────────────────────────────────────
class ConnectionManager:
    """Manages WebSocket connections for real-time log streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()

# ─────────────────────────────────────────────────────
# Background log streamer (broadcasts new logs via WS)
# ─────────────────────────────────────────────────────
_last_broadcast_idx = 0

async def log_broadcaster():
    """Background task: broadcasts new log entries to all WebSocket clients."""
    global _last_broadcast_idx
    while True:
        await asyncio.sleep(0.1)  # Check every 100ms
        logs = engine.login_logs
        if len(logs) > _last_broadcast_idx:
            new_entries = logs[_last_broadcast_idx:]
            _last_broadcast_idx = len(logs)
            for entry in new_entries:
                await ws_manager.broadcast({"type": "log", "data": entry})
            # Also broadcast any new alerts
            if engine.alerts:
                latest_alert = engine.alerts[-1]
                await ws_manager.broadcast({"type": "alert", "data": latest_alert})


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background broadcaster when app starts."""
    task = asyncio.create_task(log_broadcaster())
    yield
    task.cancel()

# ─────────────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────────────
app = FastAPI(
    title="Brute Force Detection API",
    description="Real-time brute force attack detection with ML-based anomaly scoring.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR)

# ─────────────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────────────
class LoginAttempt(BaseModel):
    ip: str = Field(..., example="192.168.1.100")
    username: str = Field(..., example="admin")
    success: bool = Field(..., example=False)
    user_agent: str = Field(default="", example="Mozilla/5.0")
    country: str = Field(default="Unknown")
    city: str = Field(default="Unknown")


class ConfigUpdate(BaseModel):
    fail_threshold: Optional[int] = None
    time_window: Optional[int] = None
    dist_threshold: Optional[int] = None
    stuffing_threshold: Optional[int] = None


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class SimulationRequest(BaseModel):
    mode: str = Field(default="mixed", description="brute_force | distributed | stuffing | mixed")


# ─────────────────────────────────────────────────────
# Auth Helpers
# ─────────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(username: str, password: str):
    user = ADMIN_USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=60))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = ADMIN_USERS.get(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


# ─────────────────────────────────────────────────────
# Rate limiting (simple in-memory)
# ─────────────────────────────────────────────────────
_rate_limit_store: dict = {}  # ip -> list of request timestamps

def check_rate_limit(request: Request, max_requests: int = 100, window: int = 60):
    """Simple sliding window rate limiter."""
    client_ip = request.client.host
    now = time.time()
    timestamps = _rate_limit_store.get(client_ip, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= max_requests:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps


# ─────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────

# ── Serve frontend ──────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_frontend():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"message": "Brute Force Detection API running. See /docs for API."})


# ── Auth ────────────────────────────────────────────
@app.post("/api/auth/token", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Obtain JWT access token.
    Default credentials: admin / admin123
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}


@app.get("/api/auth/me", tags=["Auth"])
async def get_me(current_user=Depends(get_current_user)):
    """Get current admin user info."""
    return {"username": current_user["username"], "role": current_user["role"]}


# ── Login Attempt Processing ─────────────────────────
@app.post("/api/login-attempt", tags=["Detection"])
async def submit_login_attempt(attempt: LoginAttempt, request: Request):
    """
    Submit a login attempt for brute force analysis.
    Returns enriched log with risk score and classification.
    """
    check_rate_limit(request)
    result = engine.process_login_attempt(
        ip=attempt.ip,
        username=attempt.username,
        success=attempt.success,
        user_agent=attempt.user_agent,
        country=attempt.country,
        city=attempt.city,
    )
    return result


# ── Dashboard Stats ──────────────────────────────────
@app.get("/api/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats():
    """Get aggregated statistics for the dashboard."""
    return engine.get_dashboard_stats()


@app.get("/api/dashboard/logs", tags=["Dashboard"])
async def get_logs(
    limit: int = 100,
    offset: int = 0,
    risk: Optional[str] = None,
    ip: Optional[str] = None,
    username: Optional[str] = None,
    attack_type: Optional[str] = None,
):
    """Get paginated and filtered login logs."""
    logs = list(reversed(engine.login_logs))  # Newest first

    # Apply filters
    if risk:
        logs = [l for l in logs if l.get("risk_label", "").lower() == risk.lower()]
    if ip:
        logs = [l for l in logs if ip in l.get("ip", "")]
    if username:
        logs = [l for l in logs if username.lower() in l.get("username", "").lower()]
    if attack_type:
        logs = [l for l in logs if l.get("attack_type", "").lower() == attack_type.lower()]

    total = len(logs)
    paged = logs[offset:offset + limit]

    return {"total": total, "offset": offset, "limit": limit, "logs": paged}


@app.get("/api/dashboard/alerts", tags=["Dashboard"])
async def get_alerts():
    """Get recent security alerts."""
    return {"alerts": list(reversed(engine.alerts)), "total": len(engine.alerts)}


# ── IP Management ────────────────────────────────────
@app.post("/api/ip/block/{ip}", tags=["IP Management"])
async def block_ip(ip: str, current_user=Depends(get_current_user)):
    """Block an IP address (requires authentication)."""
    return engine.block_ip(ip)


@app.post("/api/ip/unblock/{ip}", tags=["IP Management"])
async def unblock_ip(ip: str, current_user=Depends(get_current_user)):
    """Unblock an IP address (requires authentication)."""
    return engine.unblock_ip(ip)


@app.get("/api/ip/blocked", tags=["IP Management"])
async def get_blocked_ips():
    """Get list of all blocked IPs."""
    return {"blocked_ips": list(engine.blocked_ips), "count": len(engine.blocked_ips)}


# ── Configuration ────────────────────────────────────
@app.get("/api/config", tags=["Configuration"])
async def get_config():
    """Get current detection configuration."""
    return engine.config


@app.put("/api/config", tags=["Configuration"])
async def update_config(updates: ConfigUpdate, current_user=Depends(get_current_user)):
    """Update detection thresholds (requires authentication)."""
    if updates.fail_threshold is not None:
        engine.config["fail_threshold"] = updates.fail_threshold
    if updates.time_window is not None:
        engine.config["time_window"] = updates.time_window
    if updates.dist_threshold is not None:
        engine.config["dist_threshold"] = updates.dist_threshold
    if updates.stuffing_threshold is not None:
        engine.config["stuffing_threshold"] = updates.stuffing_threshold
    return {"status": "updated", "config": engine.config}


# ── Simulation ───────────────────────────────────────
@app.post("/api/simulate", tags=["Simulation"])
async def run_simulation(req: SimulationRequest):
    """
    Simulate a brute force attack scenario.
    Modes: brute_force | distributed | stuffing | mixed
    """
    valid_modes = ["brute_force", "distributed", "stuffing", "mixed"]
    if req.mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Use: {valid_modes}")
    result = sim.run_full_simulation(mode=req.mode)
    return result


# ── Export ───────────────────────────────────────────
@app.get("/api/export/csv", tags=["Export"])
async def export_csv(current_user=Depends(get_current_user)):
    """Export all login logs as CSV file."""
    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "ip", "username", "success", "country", "city",
        "ip_fail_count", "user_fail_count", "risk_score", "risk_label",
        "attack_type", "is_distributed", "is_stuffing", "is_blocked", "user_agent"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for log in engine.login_logs:
        writer.writerow(log)

    output.seek(0)
    filename = f"brute_force_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ── WebSocket ────────────────────────────────────────
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """
    WebSocket endpoint for real-time log streaming.
    Sends new log entries and alerts as they arrive.
    """
    await ws_manager.connect(websocket)
    try:
        # Send last 20 logs on connect
        recent = engine.login_logs[-20:]
        for log in recent:
            await websocket.send_json({"type": "log", "data": log})

        # Keep connection alive, wait for disconnect
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Health ───────────────────────────────────────────
@app.get("/api/health", tags=["System"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_logs": len(engine.login_logs),
        "active_connections": len(ws_manager.active_connections),
        "blocked_ips": len(engine.blocked_ips),
    }


# ── Clear Logs ───────────────────────────────────────
@app.delete("/api/logs/clear", tags=["Dashboard"])
async def clear_logs(current_user=Depends(get_current_user)):
    """Clear all logs and reset state (requires authentication)."""
    engine.login_logs.clear()
    engine.alerts.clear()
    engine.ip_fail_window.clear()
    engine.user_fail_window.clear()
    engine.ip_usernames.clear()
    engine.blocked_ips.clear()
    return {"status": "cleared", "timestamp": datetime.now(timezone.utc).isoformat()}


# ─────────────────────────────────────────────────────
# Serve static frontend files
# ─────────────────────────────────────────────────────
if os.path.exists(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
