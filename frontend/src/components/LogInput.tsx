import React, { useState, useRef } from 'react';
import '../styles/LogInput.css';

interface LogInputProps {
  onAnalyze: (logText: string) => void;
  onAnalyzeFile?: (file: File) => void;
  isLoading: boolean;
}

export const LogInput: React.FC<LogInputProps> = ({ onAnalyze, onAnalyzeFile, isLoading }) => {
  const [logText, setLogText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedFile && onAnalyzeFile) {
      onAnalyzeFile(selectedFile);
    } else if (logText.trim()) {
      onAnalyze(logText);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setLogText('');
    }
  };

  const handleClearFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
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
            onChange={(e) => {
              setLogText(e.target.value);
              if (selectedFile) setSelectedFile(null);
            }}
            placeholder="Enter security log, event, or alert message..."
            disabled={isLoading || !!selectedFile}
            rows={4}
          />
        </div>
        <div style={{ marginBottom: '1rem' }}>
          <input
            type="file"
            accept=".txt,.log,.json,.csv"
            ref={fileInputRef}
            style={{ display: 'none' }}
            onChange={handleFileChange}
            disabled={isLoading}
          />
          <button
            type="button"
            className="btn-analyze"
            style={{ background: '#23273a', color: '#90caf9', marginBottom: 8, marginRight: 8, fontWeight: 600, border: '1.5px solid #1976d2' }}
            onClick={() => fileInputRef.current?.click()}
            disabled={isLoading}
          >
            {selectedFile ? 'Change Log File' : 'Upload Log File'}
          </button>
          {selectedFile && (
            <span style={{ color: '#fff', background: '#1976d2', borderRadius: 8, padding: '0.2em 0.7em', marginRight: 8, fontWeight: 600 }}>
              {selectedFile.name}
              <button type="button" onClick={handleClearFile} style={{ marginLeft: 8, color: '#fff', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 700 }}>×</button>
            </span>
          )}
        </div>
        <div className="button-group">
          <button
            type="submit"
            disabled={isLoading || (!logText.trim() && !selectedFile)}
            className="btn-analyze"
          >
            {isLoading ? 'Analyzing...' : selectedFile ? 'Analyze File' : 'Analyze Log'}
          </button>
        </div>
      </form>
    </div>
  );
};
