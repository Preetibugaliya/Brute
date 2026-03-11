# BruteShield — Brute Force Attack Detection Tool
## 🛡️ Professional Cybersecurity Dashboard

A production-ready, full-stack brute force detection system with AI-enhanced anomaly scoring, real-time monitoring, and a stunning cybersecurity dashboard.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Server
**Windows (double-click):**
```
start.bat
```

**or via terminal:**
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open Dashboard
Navigate to [http://localhost:8000](http://localhost:8000)

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

---

## 📁 Project Structure

```
Brute force detection/
├── backend/
│   ├── main.py               # FastAPI app, JWT auth, WebSocket, REST APIs
│   ├── detection_engine.py   # Core detection logic + Isolation Forest ML
│   └── simulator.py          # Attack simulation (brute force, distributed, stuffing)
├── frontend/
│   ├── index.html            # Single-page dashboard UI
│   ├── style.css             # Cybersecurity dark theme, animations, responsive
│   └── app.js                # Dashboard logic, charts, WebSocket, auth
├── requirements.txt
├── start.bat                 # Quick-start script (Windows)
└── README.md
```

---

## 🔧 Features

### Detection Engine
| Feature | Details |
|---|---|
| **Classic Brute Force** | Same IP, many failed logins within time window |
| **Distributed BF** | Multiple IPs targeting one account |
| **Credential Stuffing** | One IP, many different usernames |
| **ML Anomaly Score** | Isolation Forest — risk score 0-100 |
| **Auto Classification** | Normal / Suspicious / High Risk Attack |
| **Configurable Thresholds** | Adjustable via dashboard |

### Dashboard
| Feature | Details |
|---|---|
| **Live Metrics** | Total requests, failed logins, active attacks, blocked IPs |
| **Charts** | Timeline, Risk Distribution (Doughnut), Top IPs (Horizontal Bar) |
| **Risk Heatmap** | Color-coded cells showing risk scores |
| **WebSocket Stream** | Real-time log table with row highlighting |
| **Toast Alerts** | Pop-up alerts with sound (Web Audio API) |
| **Search & Filter** | Filter by IP, username, risk level, attack type |
| **Export CSV** | Download all logs |
| **Block IP** | One-click IP blocking with simulated firewall |

### API Endpoints
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/token` | Get JWT token |
| `POST` | `/api/login-attempt` | Submit login event |
| `GET` | `/api/dashboard/stats` | Dashboard statistics |
| `GET` | `/api/dashboard/logs` | Paginated + filtered logs |
| `POST` | `/api/simulate` | Run attack simulation |
| `POST` | `/api/ip/block/{ip}` | Block an IP |
| `PUT` | `/api/config` | Update thresholds |
| `GET` | `/api/export/csv` | Export logs as CSV |
| `WS` | `/ws/logs` | Real-time WebSocket stream |

---

## ⚙️ Configuration

Tune in the **Configuration** tab in the dashboard, or via API:

| Parameter | Default | Description |
|---|---|---|
| `fail_threshold` | 5 | Failed attempts before flagging |
| `time_window` | 120s | Sliding window for counting |
| `dist_threshold` | 3 | Min IPs for distributed BF |
| `stuffing_threshold` | 10 | Unique usernames per IP = stuffing |

---

## 🤖 ML Model

- **Algorithm**: Isolation Forest (scikit-learn)
- **Features**: Failure frequency, average time gap, unique usernames, IP reputation
- **Training**: Online — trains from incoming data automatically (after 20+ samples)
- **Fallback**: Heuristic scoring when insufficient data
- **Score**: 0 (safe) → 100 (highly anomalous)

---

## 🔒 Security Notes

- JWT tokens expire in 60 minutes
- Rate limiting: 100 requests/minute per IP
- All admin actions require authentication
- Passwords stored as bcrypt hashes
- **For production**: Change `SECRET_KEY` in `main.py`, use a real database, and enable HTTPS

---

## 📸 Simulation Modes

| Mode | Description |
|---|---|
| `brute_force` | Single IP, 8-20 rapid failures on one account |
| `distributed` | 6 IPs attacking one account |
| `stuffing` | 1 IP, 15-25 different usernames |
| `mixed` | Combination of all above + normal traffic |

---

*Built for educational and defensive cybersecurity purposes.*
