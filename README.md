# 🛡️ Multi Agentic System
 - Complete System

Advanced AI-powered threat detection and response system combining:
- **Agent 1**: Log Classification (LSTM + Word2Vec)
- **MITRE Mapper**: ATT&CK Technique Mapping
- **Agent 2**: Automated Response Decision Engine
- **React Frontend**: Modern Dashboard

## 📋 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   React Dashboard (Port 5173)               │
│              (Security Log Analysis Interface)              │
└─────────────────────┬───────────────────┬───────────────────┘
                      │                   │
                  POST /analyze      GET /stats
                      │                   │
┌─────────────────────┴───────────────────┴───────────────────┐
│           Python Backend (Port 8000)                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Agent 1    │  │ MITRE Mapper │  │   Agent 2    │      │
│  │              │  │              │  │              │      │
│  │ Classification→ Technique Map  → Response Decide │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│     (TensorFlow)     (ATT&CK DB)    (Policy Engine)         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### One-Command Startup (Windows PowerShell)

```powershell
cd c:\Users\Admin\Documents\Agent-1
.\start-services.ps1
```

Or with batch file:
```cmd
start-services.bat
```

### Manual Startup

**Terminal 1 - Backend:**
```powershell
cd c:\Users\Admin\Documents\Agent-1
.\venv\Scripts\Activate.ps1
python run_pipeline.py --log "your log message"
```

**Terminal 2 - Frontend:**
```powershell
cd c:\Users\Admin\Documents\Agent-1\frontend
npm run dev
```

Then open: **http://localhost:5173**

## 📦 Installation

### Prerequisites
- Python 3.11+
- Node.js 16+
- npm 7+

### Backend Setup
```powershell
cd c:\Users\Admin\Documents\Agent-1

# Create virtual environment
py -3.11 -m venv venv

# Activate and install
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Frontend Setup
```powershell
cd c:\Users\Admin\Documents\Agent-1\frontend
npm install
```

## 💻 Usage

### Web Dashboard

1. **Enter a Log**: Paste or type a security event/alert
2. **Analyze**: Click "Analyze Log"
3. **View Results**:
   - 📊 **Classification**: Type and confidence score
   - ⚠️ **Threat Score**: Risk assessment (0-100)
   - 🎯 **MITRE Mapping**: ATT&CK techniques detected
   - 🤖 **Response**: Recommended actions

### example Logs to Try

```
suspicious process execution detected
unauthorized admin access attempt
malware signature detected in network traffic
privilege escalation attack blocked
```

## 🗂️ Project Structure

```
Agent-1/
├── Backend (Python)
│   ├── agent1_interface.py        # Log classification model
│   ├── mitre_engine.py            # ATT&CK mapping
│   ├── decision_engine.py         # Response decisions
│   ├── main_orchestrator.py       # Pipeline coordinator
│   ├── requirements.txt           # Python dependencies
│   ├── config.yaml                # Configuration
│   ├── lstm_log_classifier.h5     # Trained LSTM model
│   └── *.json/*.pkl               # Knowledge bases & models
│
├── Frontend (React + TypeScript)
│   ├── frontend/
│   │   ├── src/
│   │   │   ├── components/        # React components
│   │   │   ├── services/          # API service
│   │   │   ├── styles/            # Component CSS
│   │   │   ├── App.tsx            # Main app
│   │   │   └── main.tsx           # Entry point
│   │   ├── package.json           # Dependencies
│   │   ├── vite.config.ts         # Build config
│   │   └── .env.local             # Environment
│
├── start-services.ps1             # Quick launcher
├── start-services.bat             # Windows batch launcher
└── README.md                       # This file
```

## 🔧 Configuration

### Environment Variables (Frontend)

Edit `frontend/.env.local`:
```env
# Backend API URL
VITE_API_URL=http://localhost:8000
```

### Backend Configuration

Edit `config.yaml`:
```yaml
agents:
  agent1:
    enabled: true
    confidence_threshold: 0.7
  agent2:
    enabled: true
    response_mode: "auto"  # auto, manual, hybrid

mitre:
  risk_thresholds:
    critical: 80
    high: 60
    medium: 40
    low: 20

api:
  enabled: true
  host: "127.0.0.1"
  port: 8000
```

## 📊 Pipeline Workflow

```
Input Log
    ↓
┌────────────────────────┐
│  Agent 1: Classify    │ → Extracts IOCs
│  (LSTM Model)         │ → Confidence Score
│  (TensorFlow 2.21)    │
└────────┬───────────────┘
         ↓
┌────────────────────────┐
│ MITRE Mapper: Map     │ → Technique ID
│ ATT&CK Techniques     │ → Tactic
│ (STIX2 Framework)     │ → Risk Score
└────────┬───────────────┘
         ↓
┌────────────────────────┐
│  Agent 2: Respond     │ → Isolation
│  (Policy Engine)      │ → Blocking
│  (Automatic Actions)  │ → Alerting
└────────┬───────────────┘
         ↓
    Output Results
 (UI Display + JSON)
```

## 🎯 Features

### Classification
- ✅ Log type detection (Normal, Suspicious, Malicious)
- ✅ IOC extraction (IPs, hashes, URLs, domains)
- ✅ Confidence scoring
- ✅ Real-time processing

### MITRE Mapping
- ✅ ATT&CK technique detection
- ✅ Tactic identification
- ✅ Risk scoring
- ✅ Threat level assessment

### Response Automation
- ✅ Endpoint isolation
- ✅ IP blocking
- ✅ File quarantine
- ✅ SOC alerting
- ✅ Manual investigation escalation

### Frontend UI
- ✅ Real-time analysis
- ✅ Visual threat scoring
- ✅ Responsive design
- ✅ Example log templates
- ✅ Loading states
- ✅ Error handling

## 📡 API Endpoints

### Analyze Log
```http
POST /analyze HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{
  "log": "suspicious process execution detected"
}
```

Response:
```json
{
  "pipeline_run_id": "PIPE-1234567890",
  "timestamp": "2026-03-08T12:00:00Z",
  "log_id": "abc12345",
  "agent1": {
    "label": "Suspicious",
    "confidence": 0.85,
    "iocs": ["192.168.1.100"]
  },
  "mitre": {
    "mitre_techniques": [
      {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "confidence": 0.80,
        "tactic": "Execution"
      }
    ],
    "risk_score": 75.0,
    "primary_tactic": "Execution",
    "threat_level": "High"
  },
  "agent2": {
    "actions": ["monitor_only", "alert_soc"]
  },
  "summary": {
    "threat_level": "High",
    "primary_technique": "T1059",
    "immediate_action": "alert_soc",
    "requires_attention": true
  }
}
```

## 🔒 Security

- ✅ Type-safe TypeScript
- ✅ Input validation
- ✅ HTTPS ready
- ✅ CORS configured
- ✅ Secure headers

## 🚨 Troubleshooting

### Port Already in Use
```powershell
# Kill process on port 5173
Get-Process | Where-Object {$_.Name -match "node"} | Stop-Process

# Kill process on port 8000
Get-NetTCPConnection -LocalPort 8000 | Select-Object -First 1 | Stop-Process
```

### Backend Connection Failed
- Check backend is running: `http://localhost:8000`
- Verify `VITE_API_URL` in `.env.local`
- Check browser console for detailed errors

### Python Dependencies Error
```powershell
.\venv\Scripts\Activate.ps1
pip install --upgrade -r requirements.txt --no-cache-dir
```

### npm Issues
```powershell
cd frontend
rm -r node_modules package-lock.json
npm install
```

## 📚 Documentation

- Backend: See [main_orchestrator.py](main_orchestrator.py)
- Frontend: See [frontend/README.md](frontend/README.md)
- Setup: See [frontend/FRONTEND_SETUP.md](frontend/FRONTEND_SETUP.md)

## 🔄 Development Workflow

1. **Make Backend Changes**: Edit Python files
2. **Restart Backend**: Kill terminal and run again
3. **Make Frontend Changes**: Edit React/CSS files
4. **Auto-Reload**: Vite automatically reloads changes

## 📈 Performance

- **Analysis Time**: 5-15 seconds (TensorFlow model load + inference)
- **Response Time**: <500ms (after model loaded)
- **Frontend Bundle**: 202 KB JS + 13 KB CSS
- **Browser Support**: Chrome 90+, Firefox 88+, Safari 14+

## 👥 Team

- **Agent 1**: Log Classification (LSTM + Word2Vec)
- **MITRE Mapper**: Threat Intelligence (ATT&CK Framework)
- **Agent 2**: Response Orchestration (Policy Engine)
- **Frontend**: React Dashboard (TypeScript + Vite)

## 📄 License

MIT License

## 🤝 Contributing

Contributions welcome! Please:
1. Create a feature branch
2. Make changes
3. Test thoroughly
4. Submit a pull request

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Review log files in `output/results.json`
3. Check browser console for frontend errors
4. Check terminal output for backend errors

---

**Last Updated**: March 8, 2026  
**Version**: 1.0.0
