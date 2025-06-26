from typing import Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# Define log types based on decoder analysis
class LogType(Enum):
    CISCO_ASA = "cisco_asa"
    FORTIGATE = "fortigate"
    SOPHOS = "sophos"
    SYMANTEC = "symantec"
    PALOALTO = "paloalto"
    F5_BIGIP = "f5_bigip"
    KASPERSKY = "kaspersky"

@dataclass
class ParsedLog:
    timestamp: datetime
    log_type: LogType
    action: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration: Optional[int] = None
    threat_name: Optional[str] = None
    severity: Optional[str] = None
    src_country: Optional[str] = None
    dst_country: Optional[str] = None
    user: Optional[str] = None
    file_path: Optional[str] = None
    raw_log: Optional[str] = None
    policy_id: Optional[str] = None
    interface_in: Optional[str] = None
    interface_out: Optional[str] = None