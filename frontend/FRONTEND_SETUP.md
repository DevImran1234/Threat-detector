# Frontend Setup & Running Instructions

## Quick Start

### 1. Install Dependencies
```powershell
cd c:\Users\Admin\Documents\Agent-1\frontend
npm install
```

### 2. Configure Backend API

Edit `.env.local` to point to your backend:
```env
VITE_API_URL=http://localhost:8000
```

### 3. Run Development Server

**Option A: Command Line**
```powershell
npm run dev
```

**Option B: VS Code Tasks**
- Press `Ctrl+Shift+B` or use **Terminal → Run Task** → **dev**

The frontend will start at: **http://localhost:5173**

### 4. Build for Production

```powershell
npm run build
npm run preview
```

## Integration with Backend

The frontend expects these API endpoints from the Python backend:

1. **POST /analyze** - Send logs for analysis
   ```json
   {
     "log": "suspicious process execution detected"
   }
   ```

2. **GET /health** - Health check
   ```json
   {
     "status": "ok"
   }
   ```

3. **GET /stats** - Get pipeline statistics

### Start Backend
```powershell
cd c:\Users\Admin\Documents\Agent-1
.\venv\Scripts\Activate.ps1

# Option 1: Interactive mode
python run_pipeline.py

# Option 2: API Server mode (for frontend)
python main.py --api
```

## Project Structure

```
frontend/
├── public/             # Static assets
├── src/
│   ├── components/     # React components
│   │   ├── LogInput.tsx
│   │   ├── ClassificationCard.tsx
│   │   ├── ThreatScoreGauge.tsx
│   │   ├── MITRETechniquesPanel.tsx
│   │   └── ResponseActionsPanel.tsx
│   ├── services/       # API service
│   │   └── api.ts
│   ├── styles/         # Component styles
│   ├── App.tsx         # Main application
│   └── main.tsx        # Entry point
├── dist/               # Production build
├── .env.local          # Configuration
├── vite.config.ts      # Vite configuration
└── tsconfig.json       # TypeScript configuration
```

## Features

✅ Security log classification  
✅ MITRE ATT&CK technique mapping  
✅ Threat scoring with visual gauge  
✅ Recommended response actions  
✅ Real-time analysis feedback  
✅ Responsive design  
✅ Dark/Light mode ready  

## Troubleshooting

### Port Already in Use
```powershell
# Find process using port 5173
netstat -ano | findstr :5173
taskkill /PID <PID> /F
```

### Backend Connection Error
- Ensure backend is running on configured API URL
- Check VITE_API_URL in .env.local
- Browser console shows detailed error messages

### Build Errors
```powershell
# Clear cache and rebuild
rm -r node_modules dist
npm install
npm run build
```

## Technology Stack

- **React** 18+ - UI Framework
- **TypeScript** - Type Safety
- **Vite** 7 - Build Tool
- **CSS3** - Styling with Grid & Flexbox
- **Fetch API** - HTTP Client
