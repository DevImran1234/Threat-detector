import { useState, useEffect } from 'react';
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
          <h1>🛡️ MITRE Security Pipeline</h1>
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

        <div className="content-grid">
          <aside className="sidebar">
            <LogInput onAnalyze={handleAnalyzeLog} isLoading={isLoading} />
          </aside>

          <article className="main-content">
            {!result ? (
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <h2>Enter a security log to begin analysis</h2>
                <p>
                  The MITRE Security Pipeline will classify the log, map it to ATT&CK
                  techniques, and recommend response actions.
                </p>
              </div>
            ) : (
              <div className="results-container">
                <div className="results-header">
                  <h2>Analysis Results</h2>
                  <div className="metadata">
                    <span>ID: {result.log_id}</span>
                    <span>Time: {(result.processing_time * 1000).toFixed(0)}ms</span>
                  </div>
                </div>

                <div className="results-grid">
                  <div className="grid-item span-2">
                    <ClassificationCard classification={result.agent1} />
                  </div>

                  <div className="grid-item">
                    <ThreatScoreGauge
                      score={result.mitre.risk_score}
                      threatLevel={result.summary.threat_level}
                    />
                  </div>

                  <div className="grid-item span-2">
                    <MITRETechniquesPanel result={result.mitre} />
                  </div>

                  {/* External Threat Intelligence Section */}
                  <div className="grid-item span-2">
                    <div className="external-intel-panel">
                      <h3>🌐 External Threat Intelligence</h3>
                      {intelLoading ? (
                        <div>Loading external intelligence...</div>
                      ) : externalIntel && !externalIntel.error ? (
                        <pre style={{ whiteSpace: 'pre-wrap', background: '#f8f8f8', padding: '1em', borderRadius: '8px' }}>{JSON.stringify(externalIntel, null, 2)}</pre>
                      ) : (
                        <div style={{ color: 'red' }}>{externalIntel?.error}</div>
                      )}
                    </div>
                  </div>

                  {/* Anomaly Detection Section */}
                  <div className="grid-item span-2">
                    <div className="anomaly-detection-panel">
                      <h3>🧬 Anomaly Detection</h3>
                      {anomalyLoading ? (
                        <div>Detecting anomaly...</div>
                      ) : anomalyResult && !anomalyResult.error ? (
                        <pre style={{ whiteSpace: 'pre-wrap', background: '#f8f8f8', padding: '1em', borderRadius: '8px' }}>{JSON.stringify(anomalyResult, null, 2)}</pre>
                      ) : (
                        <div style={{ color: 'red' }}>{anomalyResult?.error}</div>
                      )}
                    </div>
                  </div>

                  <div className="grid-item span-2">
                    <ResponseActionsPanel actions={result.agent2.actions} />
                  </div>
                </div>
              </div>
            )}
          </article>
        </div>
      </main>

      <footer className="app-footer">
        <p>MITRE Security Pipeline v1.0 | Powered by Agent 1 (Classification) → MITRE Mapper → Agent 2 (Response)</p>
      </footer>
    </div>
  );
}

export default App;
