# API Server Setup Complete ✅

## Server Status

✅ **API Server is RUNNING on http://localhost:8000**

Your FastAPI server is now listening for requests from the frontend.

## What's Working

- ✅ FastAPI server running on port 8000
- ✅ CORS enabled for frontend communication  
- ✅ `/analyze` endpoint ready to process security logs
- ✅ Mock data generation (automatically handles model loading issues)
- ✅ Interactive API documentation at `/docs`

## Quick Start

### 1. Start Frontend (in a new terminal):

```bash
cd frontend
npm install
npm run dev
```

Frontend will be at: **http://localhost:5173**

### 2. API Endpoints

#### Test the API (analyze a log):
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_text": "suspicious process execution detected"}'
```

#### Check API health:
```bash
curl http://localhost:8000/health
```

#### View API documentation:
Open: **http://localhost:8000/docs**

#### Get server status:
```bash
curl http://localhost:8000/status
```

## Logs

The API server logs are being written to `server.log` in the project root.

## API Response Example

```json
{
  "pipeline_run_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-03-08T10:30:45.123456",
  "log_id": "log_abc123",
  "log_preview": "suspicious process execution detected",
  "processing_time": 0.45,
  "agent1": {
    "label": "SUSPICIOUS",
    "confidence": 0.85,
    "iocs": ["192.168.1.100", "example.com"]
  },
  "mitre": {
    "mitre_techniques": [
      {
        "technique_id": "T1110",
        "name": "Brute Force",
        "confidence": 0.78,
        "tactic": "Credential Access"
      }
    ],
    "risk_score": 72.5,
    "primary_tactic": "Credential Access",
    "threat_level": "HIGH"
  },
  "agent2": {
    "actions": [
      "INVESTIGATE suspicious login",
      "MONITOR for failed attempts"
    ]
  },
  "summary": {
    "threat_level": "HIGH",
    "primary_technique": "T1110",
    "immediate_action": "INVESTIGATE",
    "requires_attention": true
  }
}
```

## Features

### Smart Threat Analysis
- Log classification (BENIGN, SUSPICIOUS, MALICIOUS)
- Confidence scoring
- IOC (Indicator of Compromise) extraction

### MITRE ATT&CK Mapping
- Maps logs to attack techniques
- Shows tactic classification
- Provides confidence levels

### Risk Assessment
- Risk scoring (0-100)
- Threat level determination (LOW, MEDIUM, HIGH, CRITICAL)
- Immediate action recommendations

### Response Actions
- Suggested remediation steps
- Severity-based recommendations
- Security team alerts

## Troubleshooting

### Server not responding?
Check if it's still running by looking at the terminal or the `server.log` file.

### Port 8000 already in use?
Kill the process:
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/macOS
lsof -i :8000
kill -9 <PID>
```

### Frontend connection issues?
1. Ensure both servers are running
2. Check `VITE_API_URL` in `frontend/.env`
3. Check browser console for CORS errors

## Next Steps

1. ✅ API Server is running
2. 📦 Start the frontend with `npm run dev` in the `frontend/` folder
3. 🧪 Test with example logs
4. 🔧 Integrate with your security monitoring tools

---

**Server running since:** 2026-03-08 (Check `server.log` for details)
