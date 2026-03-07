"""
Shared data interfaces for MITRE Security Pipeline
Pydantic models for data validation and serialization
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class LogSeverity(str, Enum):
    """Log severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCType(str, Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILE_PATH = "file_path"
    CMD = "cmd"
    PORT = "port"
    REGISTRY = "registry"
    PROCESS = "process"

class IOC(BaseModel):
    """Indicator of Compromise"""
    type: IOCType
    value: str
    context: Optional[str] = None
    position: Optional[int] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    
    @validator('value')
    def validate_value(cls, v, values):
        """Validate IOC value based on type"""
        if 'type' in values:
            ioc_type = values['type']
            
            if ioc_type == IOCType.IP:
                import re
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                if not re.match(ip_pattern, v):
                    raise ValueError(f"Invalid IP address: {v}")
            
            elif ioc_type == IOCType.DOMAIN:
                if len(v) > 253:
                    raise ValueError(f"Domain too long: {v}")
                
            elif ioc_type == IOCType.HASH:
                hash_length = len(v)
                if hash_length not in [32, 40, 64]:
                    raise ValueError(f"Invalid hash length: {hash_length}")
        
        return v

class Agent1Output(BaseModel):
    """Output from Agent 1 (Log Classification)"""
    log_id: str
    timestamp: datetime
    raw_log: str
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: LogSeverity
    iocs: List[IOC] = []
    features: Optional[Dict[str, Any]] = {}
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class MITRETechnique(BaseModel):
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str  # 'rule_based', 'ioc_based', 'classification'
    matched_pattern: Optional[str] = None
    description: Optional[str] = None
    
    @validator('technique_id')
    def validate_technique_id(cls, v):
        """Validate MITRE technique ID format"""
        if not (v.startswith('T') and v[1:].isdigit()):
            raise ValueError(f"Invalid MITRE technique ID: {v}")
        return v

class MITREMapping(BaseModel):
    """MITRE Mapping Results"""
    mitre_techniques: List[MITRETechnique] = []
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    primary_tactic: str = "None"
    technique_count: int = Field(default=0, ge=0)
    mapping_methods: Dict[str, int] = {}

class ResponseAction(BaseModel):
    """Response Action"""
    action: str
    description: str
    priority: int = Field(default=3, ge=1, le=5)
    estimated_time: int = Field(default=10, ge=1)  # in seconds
    status: str = "pending"  # pending, executing, completed, failed
    
    @validator('action')
    def validate_action(cls, v):
        """Validate action name"""
        allowed_actions = [
            'isolate_endpoint', 'block_ip', 'quarantine_file', 'alert_soc',
            'collect_forensics', 'block_command_line', 'increase_monitoring',
            'kill_process', 'update_firewall', 'create_incident', 'monitor_only'
        ]
        if v not in allowed_actions:
            raise ValueError(f"Invalid action: {v}. Must be one of {allowed_actions}")
        return v

class Agent2Output(BaseModel):
    """Output from Agent 2 (Decision and Response)"""
    alert_id: str
    timestamp: datetime
    policy_used: str
    actions: List[str] = []
    priority: int = Field(default=3, ge=1, le=5)
    execution_plan: List[Dict[str, Any]] = []
    status: str = "pending"  # pending, executing, completed
    execution_results: Optional[List[Dict[str, Any]]] = []
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class PipelineResult(BaseModel):
    """Complete pipeline result"""
    pipeline_run_id: str
    timestamp: datetime
    log_id: str
    log_preview: str
    processing_time: float
    
    agent1: Agent1Output
    mitre: MITREMapping
    agent2: Agent2Output
    
    summary: Dict[str, Any]
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

# Utility functions for serialization
def to_json(obj: BaseModel) -> str:
    """Convert Pydantic model to JSON string"""
    return obj.json()

def from_json(json_str: str, model_class: BaseModel) -> BaseModel:
    """Create Pydantic model from JSON string"""
    return model_class.parse_raw(json_str)

def to_dict(obj: BaseModel) -> Dict:
    """Convert Pydantic model to dictionary"""
    return obj.dict()

def from_dict(data: Dict, model_class: BaseModel) -> BaseModel:
    """Create Pydantic model from dictionary"""
    return model_class(**data)