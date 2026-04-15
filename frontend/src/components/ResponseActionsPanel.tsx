import React from 'react';
import '../styles/ResponseActionsPanel.css';

interface ResponseActionsPanelProps {
  actions: string[];
  filename?: string;
  onRemoveFile?: (filename: string) => void;
}

export const ResponseActionsPanel: React.FC<ResponseActionsPanelProps> = ({
  actions,
  filename,
  onRemoveFile,
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
              <div
                key={idx}
                className={`action-item${idx === 0 ? ' selected' : ''}`}
                style={
                  idx === 0
                    ? {
                        background: '#fff',
                        color: '#222',
                        border: '2px solid #1976d2',
                        boxShadow: '0 2px 12px rgba(25, 118, 210, 0.08)',
                        fontWeight: 700,
                        transition: 'all 0.2s',
                      }
                    : {
                        background: '#181c26',
                        color: '#b0b8c9',
                        border: '1px solid #31374a',
                        fontWeight: 600,
                        transition: 'all 0.2s',
                      }
                }
              >
                <div className="action-icon" style={idx === 0 ? { color: '#1976d2', fontSize: '1.3rem' } : { color: '#b0b8c9', fontSize: '1.1rem' }}>
                  {getActionIcon(action)}
                </div>
                <div className="action-details">
                  <div className="action-name" style={idx === 0 ? { color: '#1976d2', fontWeight: 800, fontSize: '1.08rem' } : { color: '#b0b8c9', fontWeight: 700 }}>
                    {action.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  <div className="action-description" style={idx === 0 ? { color: '#333', fontWeight: 600 } : { color: '#b0b8c9', fontWeight: 500 }}>
                    {getActionDescription(action)}
                  </div>
                </div>
                <div className="action-status">
                  <span className="badge pending" style={idx === 0 ? { background: '#fff3e0', color: '#ff9800', fontWeight: 700 } : { background: '#23273a', color: '#ff9800', fontWeight: 600 }}>
                    READY
                  </span>
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
          {/* <button className="btn btn-primary">EXECUTE SELECTED ACTIONS</button>
          <button className="btn btn-secondary">REVIEW DETAILS</button> */}
          {filename && onRemoveFile && (
            <button className="btn btn-danger" onClick={() => onRemoveFile(filename)} style={{ marginLeft: 8 }}>
              🗑️ Remove Uploaded File
            </button>
          )}
        </div>
      )}
    </div>
  );
};
