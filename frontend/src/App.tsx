// Helper to render anomaly detection result in a readable format
function renderAnomalyResult(anomaly: any) {
  if (!anomaly || typeof anomaly !== 'object') return null;
  if (typeof anomaly === 'string') return <span>{anomaly}</span>;
  if (anomaly.error) return <span style={{ color: 'red' }}>{anomaly.error}</span>;

  return (
    <div style={{
      background: 'linear-gradient(135deg, #101522 60%, #1a2236 100%)',
      border: '1px solid #223',
      borderRadius: '14px',
      padding: '1.5em 2em',
      margin: '1em 0',
      color: '#e3f2fd',
      fontSize: '1.08em',
      boxShadow: '0 4px 24px rgba(20,30,60,0.18)',
      width: '100%',
      maxWidth: '900px',
      overflowX: 'auto',
    }}>
      {Object.entries(anomaly).map(([key, value]) => (
        <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.7em', marginBottom: '0.5em' }}>
          <span style={{ fontWeight: 700, color: '#ffb74d', minWidth: 160, letterSpacing: '0.01em' }}>{key.replace(/_/g, ' ')}:</span>
          <span style={{ color: '#fff', wordBreak: 'break-word', fontWeight: 500 }}>
            {typeof value === 'object' && value !== null
              ? Array.isArray(value)
                ? value.length > 0
                  ? value.join(', ')
                  : <span style={{ color: '#bdbdbd' }}>None</span>
                : (
                  <div style={{ marginLeft: 8 }}>
                    {Object.entries(value).map(([k, v]) => (
                      <div key={k}>
                        <span style={{ fontWeight: 600, color: '#ffd54f' }}>{k.replace(/_/g, ' ')}:</span> {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                      </div>
                    ))}
                  </div>
                )
              : String(value)}
          </span>
        </div>
      ))}
    </div>
  );
}
import { useState, useEffect } from 'react';
// Helper to render external threat intelligence in a readable format
function renderExternalIntel(intel: any) {
  if (!intel || typeof intel !== 'object') return null;
  // If it's a simple error or string
  if (typeof intel === 'string') return <span>{intel}</span>;
  if (intel.error) return <span style={{ color: 'red' }}>{intel.error}</span>;

  // Render as a styled card/list
  return (
    <div style={{
      background: 'linear-gradient(135deg, #101522 60%, #1a2236 100%)',
      border: '1px solid #223',
      borderRadius: '14px',
      padding: '1.5em 2em',
      margin: '1em 0',
      color: '#e3f2fd',
      fontSize: '1.08em',
      boxShadow: '0 4px 24px rgba(20,30,60,0.18)',
      width: '100%',
      maxWidth: '900px',
      overflowX: 'auto',
    }}>
      {Object.entries(intel).map(([key, value]) => (
        <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.7em', marginBottom: '0.5em' }}>
          <span style={{ fontWeight: 700, color: '#64b5f6', minWidth: 160, letterSpacing: '0.01em' }}>{key.replace(/_/g, ' ')}:</span>
          <span style={{ color: '#fff', wordBreak: 'break-word', fontWeight: 500 }}>
            {typeof value === 'object' && value !== null
              ? Array.isArray(value)
                ? value.length > 0
                  ? value.join(', ')
                  : <span style={{ color: '#bdbdbd' }}>None</span>
                : (
                  <div style={{ marginLeft: 8 }}>
                    {Object.entries(value).map(([k, v]) => (
                      <div key={k}>
                        <span style={{ fontWeight: 600, color: '#4dd0e1' }}>{k.replace(/_/g, ' ')}:</span> {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                      </div>
                    ))}
                  </div>
                )
              : String(value)}
          </span>
        </div>
      ))}
    </div>
  );
}
import type { PipelineResult } from './services/api';
import { LogInput } from './components/LogInput';
import { ClassificationCard } from './components/ClassificationCard';
import { ThreatScoreGauge } from './components/ThreatScoreGauge';
import { MITRETechniquesPanel } from './components/MITRETechniquesPanel';
import { ResponseActionsPanel } from './components/ResponseActionsPanel';
import APIService from './services/api';
import './App.css';

type ResultType = PipelineResult | null;

function App() {
  const [result, setResult] = useState<ResultType>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [isHealthy, setIsHealthy] = useState(true);

  const [externalIntel, setExternalIntel] = useState<any>(null);
  const [anomalyResult, setAnomalyResult] = useState<any>(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [uploadedFilename, setUploadedFilename] = useState<string | null>(null);
  const [uploadedFilePath, setUploadedFilePath] = useState<string | null>(null);
  const handleAnalyzeLogFile = async (file: File) => {
    if (!isHealthy) {
      setError('Backend service is unavailable. Please ensure the API server is running.');
      return;
    }
    setIsLoading(true);
    setError('');
    setExternalIntel(null);
    setAnomalyResult(null);
    try {
      const analysisResult = await APIService.analyzeLogFile(file);
      setResult(analysisResult);
      // Fetch external threat intelligence
      setIntelLoading(true);
      try {
        const intel = await APIService.getExternalThreatIntel(analysisResult.log_preview || '');
        setExternalIntel(intel);
      } catch (intelErr) {
        setExternalIntel({ error: 'Failed to fetch external threat intelligence.' });
      }
      setIntelLoading(false);
      // Fetch anomaly detection
      setAnomalyLoading(true);
      try {
        const anomaly = await APIService.detectAnomaly(analysisResult.log_preview || '');
        setAnomalyResult(anomaly);
      } catch (anomalyErr) {
        setAnomalyResult({ error: 'Failed to detect anomaly.' });
      }
      setAnomalyLoading(false);
      setUploadedFilename(file.name);
      // Try to get the full path if available (Electron, or custom file picker)
      // For browsers, this is not possible for security reasons, so we use the name as a fallback
      // If you have a custom upload API that returns the server path, set it here
      if ((file as any).path) {
        setUploadedFilePath((file as any).path);
      } else {
        // Assume file is saved in output/ on backend
        setUploadedFilePath(`C:/Users/Admin/Documents/Agent-1/output/${file.name}`);
      }
    } catch (err) {
      console.error('Analysis error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(
        `Failed to analyze log file: ${errorMessage}. Please check backend connection and try again.`
      );
      setResult(null);
      setIsHealthy(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRemoveUploadedFile = async (filename: string) => {
    try {
      if (!uploadedFilePath) {
        alert('No file path available for removal.');
        return;
      }
      await APIService.removeUploadedFile(uploadedFilePath);
      setUploadedFilename(null);
      setUploadedFilePath(null);
      alert(`File '${filename}' removed from server.`);
    } catch (err) {
      alert(`Failed to remove file: ${filename}`);
    }
  };

  // Check backend health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const healthy = await APIService.getHealth();
        setIsHealthy(healthy);
        if (!healthy) {
          setError('Backend service is not responding. Please ensure the API server is running.');
        }
      } catch (err) {
        setIsHealthy(false);
      }
    };

    checkHealth();
    const healthCheckInterval = setInterval(checkHealth, 30000); // Check every 30 seconds
    return () => clearInterval(healthCheckInterval);
  }, []);

  const handleAnalyzeLog = async (logText: string) => {
    if (!isHealthy) {
      setError('Backend service is unavailable. Please ensure the API server is running.');
      return;
    }

    setIsLoading(true);
    setError('');

    setExternalIntel(null);
    setAnomalyResult(null);

    try {
      const analysisResult = await APIService.analyzeLogs(logText);
      setResult(analysisResult);
      // Fetch external threat intelligence
      setIntelLoading(true);
      try {
        const intel = await APIService.getExternalThreatIntel(logText);
        setExternalIntel(intel);
      } catch (intelErr) {
        setExternalIntel({ error: 'Failed to fetch external threat intelligence.' });
      }
      setIntelLoading(false);
      // Fetch anomaly detection
      setAnomalyLoading(true);
      try {
        const anomaly = await APIService.detectAnomaly(logText);
        setAnomalyResult(anomaly);
      } catch (anomalyErr) {
        setAnomalyResult({ error: 'Failed to detect anomaly.' });
      }
      setAnomalyLoading(false);
      setUploadedFilename(null);
    } catch (err) {
      console.error('Analysis error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(
        `Failed to analyze log: ${errorMessage}. Please check backend connection and try again.`
      );
      setResult(null);
      setIsHealthy(false);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="header-content">
          <h1>🛡️ Multi Agentic System
</h1>
          <p>Advanced Threat Detection & Response System</p>
        </div>
        <div className="header-status">
          {isLoading && <span className="status-badge loading">Analyzing...</span>}
          {!isLoading && !error && isHealthy && (
            <span className="status-badge success">
              {result ? 'Ready' : 'Ready'}
            </span>
          )}
          {!isHealthy && <span className="status-badge error">Offline</span>}
          {error && !isLoading && <span className="status-badge error">Error</span>}
        </div>
      </header>

      <main className="app-main">
        {error && (
          <div className="error-banner">
            <span className="error-icon">⚠️</span>
            <div>
              <strong>Error:</strong> {error}
            </div>
          </div>
        )}

        <div className="unified-grid">
          <div className="grid-item">
            <LogInput onAnalyze={handleAnalyzeLog} onAnalyzeFile={handleAnalyzeLogFile} isLoading={isLoading} />
          </div>
          {result ? <>
            <div className="grid-item">
              <ClassificationCard classification={result.agent1} />
            </div>
            <div className="grid-item">
              <ThreatScoreGauge
                score={result.mitre.risk_score}
                threatLevel={result.summary.threat_level}
              />
            </div>
            <div className="grid-item span-3">
              <MITRETechniquesPanel result={result.mitre} />
            </div>
            <div className="grid-item span-3">
              <div className="external-intel-panel">
                <h3>🌐 External Threat Intelligence</h3>
                {intelLoading ? (
                  <div>Loading external intelligence...</div>
                ) : (
                  renderExternalIntel(externalIntel)
                )}
              </div>
            </div>
            <div className="grid-item span-3">
              <div className="anomaly-detection-panel">
                <h3>🧬 Anomaly Detection</h3>
                {anomalyLoading ? (
                  <div>Detecting anomaly...</div>
                ) : (
                  renderAnomalyResult(anomalyResult)
                )}
              </div>
            </div>
            <div className="grid-item span-3">
              <ResponseActionsPanel actions={result.agent2.actions} filename={uploadedFilename || undefined} onRemoveFile={handleRemoveUploadedFile} />
            </div>
          </> : (
            <div className="empty-state grid-item span-3">
              <div className="empty-icon">🔍</div>
              <h2>Enter a security log to begin analysis</h2>
              <p>
                The Multi Agentic System will classify the log, map it to ATT&CK
                techniques, and recommend response actions.
              </p>
            </div>
          )}
        </div>
      </main>

      <footer className="app-footer">
        <p>Multi Agentic System
 v1.0 | Powered by Agent 1 (Classification) → MITRE Mapper → Agent 2 (Response)</p>
      </footer>
    </div>
  );
}

export default App;
