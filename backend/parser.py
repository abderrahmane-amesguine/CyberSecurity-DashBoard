import re
from datetime import datetime
from typing import Optional
from parsed_log import ParsedLog, LogType
from parsers.fortigate import parse_fortigate

class SecurityLogParser:
    """
    Parser for multiple security tool logs based on Wazuh decoder patterns
    Reference: Wazuh decoders repository
    """
    
    def __init__(self):
        # Patterns derived from official Wazuh decoders
        self.patterns = {
            LogType.CISCO_ASA: {
                # Pattern from 0064-cisco-asa_decoders.xml
                'base': r'%ASA-(\d)-(\d+):\s+(.*)',
                'denied': r'Deny\s+(\w+)\s+from\s+(\S+)/(\d+)\s+to\s+(\S+)/(\d+)',
                'teardown': r'Teardown\s+(\w+)\s+connection\s+(\d+).*duration\s+(\d+:\d+:\d+)\s+bytes\s+(\d+)',
            },
            LogType.FORTIGATE: {
                # Pattern from 0100-fortigate_decoders.xml
                'v5_traffic': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*type=TRAFFIC.*action="?(\w+)"?.*srcip=(\S+).*dstip=(\S+).*sent_byte=(\d+).*rcvd_byte=(\d+)',
                'v5_threat': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*type=utm.*severity=(\w+).*virus="([^"]+)"',
            },
            LogType.PALOALTO: {
                # Pattern from 0505-paloalto_decoders.xml
                'traffic': r'(\d+/\d+/\d+\s+\d+:\d+:\d+),.*,TRAFFIC,.*,(\w+),.*,(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+),.*,(\d+),(\d+),.*,(\w+),(\w+),.*,(\d+),(\d+)',
                'threat': r'(\d+/\d+/\d+\s+\d+:\d+:\d+),.*,THREAT,.*,(\w+),.*,(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+),.*severity="(\w+)".*threat_id="([^"]+)"',
            },
            LogType.SOPHOS: {
                # Pattern from 0300-sophos_decoders.xml
                'detection': r'(\d{8}\s+\d{6})\s+.*virus\s+detected.*Name:\s+([^\s]+)',
                'scan': r'(\d{8}\s+\d{6})\s+Scan\s+\'([^\']+)\'\s+(started|completed)',
            },
            LogType.KASPERSKY: {
                # Pattern from kaspersky_decoder.xml
                'detection': r'TIMESTAMP:\s+\'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*INFECTED_HOST:\s+\'([^\']+)\'.*p5="([^"]+)".*et="(GNRL_EV_\w+)"',
            }
        }
        
    def detect_log_type(self, log_line: str) -> Optional[LogType]:
        """Detect log type based on patterns"""
        if '%ASA-' in log_line:
            return LogType.CISCO_ASA
        elif 'date=' in log_line and 'devname=' in log_line:
            return LogType.FORTIGATE
        elif 'TRAFFIC,' in log_line or 'THREAT,' in log_line:
            return LogType.PALOALTO
        elif 'Kasperky syslog pattern:' in log_line:
            return LogType.KASPERSKY
        elif re.search(r'\d{8}\s+\d{6}\s+(Scan|User|Using)', log_line):
            return LogType.SOPHOS
        return None
    
    def parse_log(self, log_line: str) -> Optional[ParsedLog]:
        """Parse a single log line"""
        log_type = self.detect_log_type(log_line)
        if not log_type:
            return None
            
        if log_type == LogType.CISCO_ASA:
            return self._parse_cisco_asa(log_line)
        elif log_type == LogType.FORTIGATE:
            return parse_fortigate(log_line, self.patterns[LogType.FORTIGATE])
        elif log_type == LogType.PALOALTO:
            return self._parse_paloalto(log_line)
        elif log_type == LogType.KASPERSKY:
            return self._parse_kaspersky(log_line)
        elif log_type == LogType.SOPHOS:
            return self._parse_sophos(log_line)
            
        return None
    
    def _parse_cisco_asa(self, log_line: str) -> Optional[ParsedLog]:
        """Parse Cisco ASA logs based on decoder patterns"""
        parsed = ParsedLog(
            timestamp=datetime.now(),
            log_type=LogType.CISCO_ASA,
            raw_log=log_line
        )
        
        # Extract deny actions - Pattern from decoder
        deny_match = re.search(self.patterns[LogType.CISCO_ASA]['denied'], log_line)
        if deny_match:
            parsed.protocol = deny_match.group(1)
            parsed.src_ip = deny_match.group(2)
            parsed.src_port = int(deny_match.group(3))
            parsed.dst_ip = deny_match.group(4)
            parsed.dst_port = int(deny_match.group(5))
            parsed.action = 'deny'
            
        # Extract teardown with bytes
        teardown_match = re.search(self.patterns[LogType.CISCO_ASA]['teardown'], log_line)
        if teardown_match:
            parsed.protocol = teardown_match.group(1)
            duration_str = teardown_match.group(3)
            parsed.bytes_sent = int(teardown_match.group(4))
            # Convert duration HH:MM:SS to seconds
            h, m, s = map(int, duration_str.split(':'))
            parsed.duration = h * 3600 + m * 60 + s
            
        return parsed
    
    
    def _parse_paloalto(self, log_line: str) -> Optional[ParsedLog]:
        """Parse Palo Alto logs based on decoder patterns"""
        # Implementation based on decoder patterns
        if 'TRAFFIC' in log_line:
            parts = log_line.split(',')
            if len(parts) > 30:
                return ParsedLog(
                    timestamp=datetime.now(),
                    log_type=LogType.PALOALTO,
                    action=parts[29] if len(parts) > 29 else None,
                    src_ip=parts[7] if len(parts) > 7 else None,
                    dst_ip=parts[8] if len(parts) > 8 else None,
                    bytes_sent=int(parts[31]) if len(parts) > 31 and parts[31].isdigit() else 0,
                    bytes_received=int(parts[32]) if len(parts) > 32 and parts[32].isdigit() else 0,
                    raw_log=log_line
                )
        return None
    
    def _parse_kaspersky(self, log_line: str) -> Optional[ParsedLog]:
        """Parse Kaspersky logs based on decoder patterns"""
        match = re.search(self.patterns[LogType.KASPERSKY]['detection'], log_line)
        if match:
            timestamp_str = match.group(1)
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            
            return ParsedLog(
                timestamp=timestamp,
                log_type=LogType.KASPERSKY,
                threat_name=match.group(3),
                action='detected',
                raw_log=log_line
            )
        return None
    
    def _parse_sophos(self, log_line: str) -> Optional[ParsedLog]:
        """Parse Sophos logs based on decoder patterns"""
        match = re.search(self.patterns[LogType.SOPHOS]['detection'], log_line)
        if match:
            timestamp_str = match.group(1)
            timestamp = datetime.strptime(timestamp_str, "%Y%m%d %H%M%S")
            
            return ParsedLog(
                timestamp=timestamp,
                log_type=LogType.SOPHOS,
                threat_name=match.group(2),
                action='detected',
                raw_log=log_line
            )
        return None
