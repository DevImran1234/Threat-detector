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
                <div key={idx} className="technique-item">
                  <div className="technique-header">
                    <span className="technique-id">{tech.technique_id}</span>
                    <span className="technique-name">{tech.name}</span>
                  </div>
                  <div className="technique-details">
                    <div className="technique-tactic">
                      <span className="label">Tactic:</span>
                      <span className="value">{tech.tactic}</span>
                    </div>
                    <div className="technique-confidence">
                      <span className="label">Confidence:</span>
                      <span className="value">
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
