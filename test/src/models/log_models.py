"""
Pydantic models for log entries and parsing results
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

class LogEntry(BaseModel):
    """Base model for parsed log entries"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    raw_log: str
    line_number: int
    cluster_id: Optional[int] = None
    template: Optional[str] = None
    
    # Common fields
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    
    # Security fields
    threat_indicators: Optional[Dict[str, List[str]]] = None
    security_action: Optional[str] = None
    severity_level: Optional[str] = 'info'
    
    # Metadata
    parser_type: str = 'drain3'
    parse_timestamp: datetime = Field(default_factory=datetime.utcnow)
    extracted_fields: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class ParseResult(BaseModel):
    """Model for complete parsing results"""
    
    file_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_name: Optional[str] = None
    parse_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Format detection
    detected_format: str
    format_confidence: float
    
    # Parsing results
    total_lines: int
    parsed_lines: int
    error_lines: int
    success_rate: float
    
    # Entries
    entries: List[LogEntry]
    parse_errors: List[Dict[str, Any]]
    
    # Cluster analysis
    clusters: List[Dict[str, Any]]
    unique_templates: int
    
    # Security insights
    security_summary: Dict[str, Any]
    threat_count: int = 0
    critical_events: int = 0
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class SecurityMetrics(BaseModel):
    """Security-specific metrics from parsed logs"""
    
    total_events: int
    threat_events: int
    blocked_events: int
    allowed_events: int
    
    severity_distribution: Dict[str, int]
    action_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]
    
    top_source_ips: List[Dict[str, Any]]
    top_destination_ips: List[Dict[str, Any]]
    top_threat_indicators: List[Dict[str, Any]]
    
    timeline: List[Dict[str, Any]]  # Events over time
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }