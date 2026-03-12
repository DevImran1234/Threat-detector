import React, { useState } from 'react';
import '../styles/LogInput.css';

interface LogInputProps {
  onAnalyze: (logText: string) => void;
  isLoading: boolean;
}

export const LogInput: React.FC<LogInputProps> = ({ onAnalyze, isLoading }) => {
  const [logText, setLogText] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (logText.trim()) {
      onAnalyze(logText);
    }
  };

  const exampleLogs = [
    'suspicious process execution detected',
    'unauthorized admin access attempt',
    'malware signature detected in network traffic',
    'privilege escalation attack blocked',
  ];

  return (
    <div className="log-input-container">
      <h2>🔍 Security Log Analysis</h2>
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <textarea
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
            placeholder="Enter security log, event, or alert message..."
            disabled={isLoading}
            rows={4}
          />
        </div>
        <div className="button-group">
          <button
            type="submit"
            disabled={isLoading || !logText.trim()}
            className="btn-analyze"
          >
            {isLoading ? 'Analyzing...' : 'Analyze Log'}
          </button>
        </div>
      </form>

      <div className="examples">
        <p>Quick examples:</p>
        <div className="example-buttons">
          {exampleLogs.map((example, idx) => (
            <button
              key={idx}
              className="example-btn"
              onClick={() => setLogText(example)}
              disabled={isLoading}
            >
              {example}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
