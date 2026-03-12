/**
 * API Service for MITRE Security Pipeline
 * Handles communication with the Python backend
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export interface Classification {
  label: string;
  confidence: number;
  iocs: string[];
}

export interface MITRETechnique {
  technique_id: string;
  name: string;
  confidence: number;
  tactic: string;
}

export interface MITREResult {
  mitre_techniques: MITRETechnique[];
  risk_score: number;
  primary_tactic: string;
  threat_level: string;
}

export interface PipelineResult {
  pipeline_run_id: string;
  timestamp: string;
  log_id: string;
  log_preview: string;
  processing_time: number;
  agent1: Classification;
  mitre: MITREResult;
  agent2: {
    actions: string[];
  };
  summary: {
    threat_level: string;
    primary_technique: string;
    immediate_action: string;
    requires_attention: boolean;
  };
}

class APIService {
  async analyzeLogs(logText: string): Promise<PipelineResult> {
    try {
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ log_text: logText }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error analyzing logs:', error);
      throw error;
    }
  }

  async getHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE_URL}/health`);
      return response.ok;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }

  async getStats(): Promise<any> {
    try {
      const response = await fetch(`${API_BASE_URL}/stats`);
      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Error fetching stats:', error);
      throw error;
    }
  }
}

export default new APIService();
