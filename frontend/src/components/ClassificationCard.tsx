import React from 'react';
import type { Classification } from '../services/api';
import '../styles/ClassificationCard.css';

interface ClassificationCardProps {
  classification: Classification;
}

export const ClassificationCard: React.FC<ClassificationCardProps> = ({
  classification,
}) => {
  if (!classification) return null;

  const confidencePercent = (classification.confidence * 100).toFixed(1);

  return (
    <div className="classification-card">
      <div className="card-header">
        <h3>📊 Log Classification</h3>
      </div>

      <div className="classification-content">
        <div className="classification-badge">
          <span className="label-text">Classification</span>
          <span className={`label-badge ${classification.label.toLowerCase()}`}>
            {classification.label}
          </span>
        </div>

        <div className="confidence-section">
          <div className="confidence-label">
            <span>Confidence Score</span>
            <span className="confidence-value">{confidencePercent}%</span>
          </div>
          <div className="confidence-bar-container">
            <div
              className="confidence-bar"
              style={{
                width: `${classification.confidence * 100}%`,
              }}
            />
          </div>
        </div>

        {classification.iocs && classification.iocs.length > 0 && (
          <div className="iocs-section">
            <h4>🔗 Indicators of Compromise (IOCs)</h4>
            <div className="iocs-list">
              {classification.iocs.map((ioc, idx) => (
                <div key={idx} className="ioc-item">
                  {ioc}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
