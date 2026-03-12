# MITRE Security Pipeline - React Frontend

A modern, responsive React.js dashboard for the MITRE Security Pipeline threat detection and response system.

## Features

- **Log Classification**: Analyze security logs with AI-powered classification
- **MITRE ATT&CK Mapping**: Map threats to MITRE ATT&CK techniques
- **Threat Scoring**: Visual threat level assessment with risk scoring
- **Response Actions**: Automated response action recommendations
- **Real-time Analysis**: Fast processing with visual feedback
- **Responsive Design**: Works on desktop, tablet, and mobile devices

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── LogInput.tsx
│   │   ├── ClassificationCard.tsx
│   │   ├── ThreatScoreGauge.tsx
│   │   ├── MITRETechniquesPanel.tsx
│   │   └── ResponseActionsPanel.tsx
│   ├── services/
│   │   └── api.ts
│   ├── styles/
│   │   ├── LogInput.css
│   │   ├── ClassificationCard.css
│   │   ├── ThreatScoreGauge.css
│   │   ├── MITRETechniquesPanel.css
│   │   └── ResponseActionsPanel.css
│   ├── App.tsx
│   ├── App.css
│   ├── main.tsx
│   └── index.css
├── .env.local
├── vite.config.ts
└── package.json
```

## Getting Started

### Prerequisites

- Node.js 16+ and npm 7+

### Installation

```bash
# Install dependencies
npm install
```

### Configuration

Edit `.env.local` to configure the backend API URL:

```env
VITE_API_URL=http://localhost:8000
```

### Development

```bash
# Start dev server
npm run dev
```

The app will be available at `http://localhost:5173`

### Build

```bash
# Create production build
npm run build

# Preview production build
npm run preview
```

## Backend Integration

The frontend communicates with the Python backend at the configured API URL. Ensure the backend is running:

```bash
# From the parent Agent-1 directory
.\venv\Scripts\Activate.ps1
python run_pipeline.py --api
```

## API Endpoints

- `POST /analyze` - Analyze a security log
- `GET /health` - Check backend health
- `GET /stats` - Get pipeline statistics

## Usage

1. Enter a security log or alert in the Log Input panel
2. Click "Analyze Log" to send it to the backend
3. View the results:
   - **Classification**: Log type and confidence score
   - **Threat Score**: Visual risk assessment
   - **MITRE Techniques**: Detected ATT&CK techniques
   - **Response Actions**: Recommended mitigation steps

## Technologies

- React 18+
- TypeScript
- Vite
- CSS3 Grid & Flexbox

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## License

MIT

import reactDom from 'eslint-plugin-react-dom'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
