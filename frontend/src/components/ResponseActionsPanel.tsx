import React from 'react';
import '../styles/ResponseActionsPanel.css';

interface ResponseActionsPanelProps {
  actions: string[];
}

export const ResponseActionsPanel: React.FC<ResponseActionsPanelProps> = ({
  actions,
}) => {
  const getActionIcon = (action: string) => {
    if (action.includes('isolate')) return '🔒';
    if (action.includes('block')) return '🚫';
    if (action.includes('alert')) return '🔔';
    if (action.includes('monitor') || action.includes('monitor_only')) return '👁️';
    if (action.includes('investigate')) return '🔍';
    if (action.includes('quarantine')) return '⛔';
    return '→';
  };

  const getActionDescription = (action: string) => {
    const descriptions: { [key: string]: string } = {
      isolate_endpoint: 'Isolate affected endpoint from network',
      block_ip: 'Block source IP address',
      quarantine_file: 'Move suspicious files to quarantine',
      alert_soc: 'Send alert to Security Operations Center',
      monitor_only: 'Continue monitoring without action',
      investigate: 'Escalate for manual investigation',
    };
    return descriptions[action] || action;
  };

  return (
    <div className="response-panel">
      <div className="panel-header">
        <h3>🤖 Recommended Response Actions</h3>
      </div>

      <div className="panel-content">
        {actions && actions.length > 0 ? (
          <div className="actions-list">
            {actions.map((action, idx) => (
              <div key={idx} className="action-item">
                <div className="action-icon">
                  {getActionIcon(action)}
                </div>
                <div className="action-details">
                  <div className="action-name">
                    {action.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  <div className="action-description">
                    {getActionDescription(action)}
                  </div>
                </div>
                <div className="action-status">
                  <span className="badge pending">READY</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-actions">
            ✓ No immediate action required
          </div>
        )}
      </div>

      {actions && actions.length > 0 && (
        <div className="action-buttons">
          <button className="btn btn-primary">Execute Selected Actions</button>
          <button className="btn btn-secondary">Review Details</button>
        </div>
      )}
    </div>
  );
};
