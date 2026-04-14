import React from 'react';
import '../styles/ThreatScoreGauge.css';

interface ThreatScoreGaugeProps {
  score: number;
  threatLevel: string;
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({
  score,
  threatLevel,
}) => {
  const getColor = () => {
    if (score >= 80) return '#d32f2f';
    if (score >= 60) return '#f57c00';
    if (score >= 40) return '#fbc02d';
    return '#388e3c';
  };

  const getThreatLevelClass = () => {
    return `threat-level ${threatLevel.toLowerCase()}`;
  };

  return (
    <div className="threat-score-container">
      <h3 style={{
        color:'#fff'
      }}>⚠️ Threat Score</h3>

      <div className="gauge-wrapper">
        <div className="gauge">
          <svg viewBox="0 0 100 100" className="gauge-svg">
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="#e0e0e0"
              strokeWidth="8"
            />
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={getColor()}
              strokeWidth="8"
              strokeDasharray={`${(score / 100) * 282.7} 282.7`}
              className="gauge-progress"
            />
            <text x="50" y="45" textAnchor="middle" className="gauge-text">
              {score.toFixed(0)}
            </text>
            <text x="50" y="60" textAnchor="middle" className="gauge-label">
              /100
            </text>
          </svg>
        </div>

        <div className={getThreatLevelClass()}>
          {threatLevel}
        </div>
      </div>

      <div className="threat-description">
        {score >= 80 && '🚨 Critical threat - Immediate action required'}
        {score >= 60 && score < 80 && '⚠️ High threat - Escalate and investigate'}
        {score >= 40 && score < 60 && '⚡ Medium threat - Review and monitor'}
        {score < 40 && '✓ Low threat - Routine monitoring'}
      </div>
    </div>
  );
};
