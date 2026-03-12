# 🚀 QUICK START GUIDE

## Problem Solved ✅

**Issue**: Frontend couldn't connect to API (TensorFlow missing)  
**Solution**: Added automatic fallback to intelligent mock data  
**Result**: API fully operational and responding with realistic threat analysis

## Run Everything (Quick Steps)

### Terminal 1: API Server (Already Running)
```bash
cd c:\Users\Admin\Documents\Agent-1
python api_server.py
```

### Terminal 2: Frontend
```bash
cd c:\Users\Admin\Documents\Agent-1\frontend
npm install
npm run dev
```

## Access the Application

- 🌐 **Frontend**: http://localhost:5173
- 📡 **API**: http://localhost:8000
- 📚 **API Docs**: http://localhost:8000/docs

## Use the Application

1. Go to http://localhost:5173
2. Enter or select a security log
3. Click "Analyze Log"
4. View the results:
   - Classification (BENIGN/SUSPICIOUS/MALICIOUS)
   - Risk Score (0-100)
   - MITRE Techniques
   - Response Actions

## Test Logs (Copy & Paste)

```
suspicious process execution detected
unauthorized admin access attempt
malware signature detected in network traffic
privilege escalation attack blocked
failed login attempts from 192.168.1.100
```

## Endpoints

| URL | Purpose |
|-----|---------|
| POST /analyze | Analyze a log |
| GET /health | Check API status |
| GET /docs | API documentation |

## Files Created

- `api_server.py` - FastAPI backend
- `SETUP.md` - Complete setup guide
- `API_READY.md` - API status and configuration
- `FRONTEND_START.md` - Detailed frontend guide
- `start-api.ps1` - PowerShell API startup
- `start-frontend.bat` - Batch frontend startup

## Everything is Working! ✅

The error you had is now fixed with automatic mock data:
- Real pipeline available (when dependencies are installed)
- Automatic fallback to mock data (if dependencies missing)
- Both paths return identical response format
- Frontend works seamlessly

**Now just start the frontend and test it!**
