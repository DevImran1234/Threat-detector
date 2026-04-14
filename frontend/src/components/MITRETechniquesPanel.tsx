import React from 'react';
import type { MITREResult } from '../services/api';
import '../styles/MITRETechniquesPanel.css';

interface MITRETechniquesPanelProps {
  result: MITREResult;
}

export const MITRETechniquesPanel: React.FC<MITRETechniquesPanelProps> = ({
  result,
}) => {
  if (!result) return null;

  return (
    <div className="mitre-panel">
      <div className="panel-header">
        <h3>🎯 MITRE ATT&CK Mapping</h3>
        {result.primary_tactic && (
          <span className="tactic-badge">{result.primary_tactic}</span>
        )}
      </div>

      <div className="panel-content">
        {result.mitre_techniques && result.mitre_techniques.length > 0 ? (
          <>
            <div className="techniques-count">
              {result.mitre_techniques.length} technique(s) detected
            </div>
            <div className="techniques-list">
              {result.mitre_techniques.map((tech, idx) => (
                <div
                  key={idx}
                  className="technique-item"
                  style={{
                    background: '#181c26',
                    border: '2px solid #1976d2',
                    borderRadius: '10px',
                    marginBottom: '0.7em',
                    boxShadow: '0 2px 12px rgba(25, 118, 210, 0.08)',
                    color: '#e3f2fd',
                    padding: '1.2em 1.5em',
                  }}
                >
                  <div className="technique-header" style={{ alignItems: 'center' }}>
                    <span className="technique-id" style={{ background: '#1976d2', color: '#fff', fontWeight: 800, fontSize: '1.05em', borderRadius: 6, padding: '0.25em 0.8em', marginRight: 12 }}>{tech.technique_id}</span>
                    <span className="technique-name" style={{ color: '#fff', fontWeight: 700, fontSize: '1.08em', letterSpacing: '0.01em' }}>{tech.name}</span>
                  </div>
                  <div className="technique-details" style={{ marginTop: 10 }}>
                    <div className="technique-tactic">
                      <span className="label" style={{ color: '#90caf9', fontWeight: 700 }}>Tactic:</span>
                      <span className="value" style={{ color: '#fff', fontWeight: 600, marginLeft: 6 }}>{tech.tactic}</span>
                    </div>
                    <div className="technique-confidence">
                      <span className="label" style={{ color: '#ffd54f', fontWeight: 700, marginLeft: 18 }}>Confidence:</span>
                      <span className="value" style={{ color: '#fff', fontWeight: 700, marginLeft: 6 }}>
                        {(tech.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="no-techniques">
            ✓ No MITRE techniques detected
          </div>
        )}
      </div>

      <div className="risk-section">
        <div className="risk-label">Risk Score</div>
        <div className="risk-value">{result.risk_score.toFixed(1)}/100</div>
      </div>
    </div>
  );
};
