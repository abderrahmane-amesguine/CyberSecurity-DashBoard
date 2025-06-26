"""
Fixed Drain3 Engine with Proper Result Handling
"""

import logging
import re
from typing import Dict, List, Optional, Any
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import json
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class UniversalDrain3Engine:
    """
    Universal log parsing engine using Drain3
    Automatically detects and parses various cybersecurity tool log formats
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the Drain3 engine with configuration"""
        self.config_path = config_path
        self.template_miner = None
        self.detected_format = None
        self.parsed_templates = {}
        self.field_extractors = {}
        self._initialize_engine()
        
    def _initialize_engine(self):
        """Initialize Drain3 template miner with configuration"""
        # Create config object
        config = TemplateMinerConfig()
        
        # Set Drain algorithm parameters
        config.drain_sim_th = 0.4  # Similarity threshold (0.4 = 40% similar to join same cluster)
        config.drain_depth = 4     # Depth of prefix tree
        config.drain_max_children = 100  # Max number of children per node
        config.drain_max_clusters = 1024  # Max number of log clusters
        
        # IMPORTANT: Set extra delimiters/separators for better tokenization
        # This tells Drain3 to split tokens on these characters
        config.drain_extra_delimiters = [
            '=',   # For key=value pairs
            ',',   # For CSV and comma-separated values
            '|',   # For pipe-delimited formats
            ';',   # For semicolon-separated values
            '[', ']',  # For bracketed content
            '(', ')',  # For parentheses
            '{', '}',  # For JSON-like content
            '<', '>',  # For XML-like tags
            '/',   # For paths
            '\\',  # For Windows paths
            '"',   # For quoted strings
            "'",   # For single quotes
            '@',   # For email addresses
            '#',   # For anchors/IDs
            '$',   # For variables
            '%',   # For encoded values
            '^',   # Various delimiters
            '&',   # For URL parameters
            '*',   # For wildcards
            '+',   # For concatenation
            '!',   # For negation
            '?',   # For queries
            '~',   # For home directories
            '`',   # For command substitution
            '\t',  # For tab-separated values
        ]
        
        # Enable numeric token parametrization
        # This replaces numbers with placeholders for better clustering
        config.parametrize_numeric_tokens = True
        
        # Masking configuration - pre-process patterns before clustering
        config.masking = [
            # Network patterns
            {"regex_pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "mask_with": "IP"},
            {"regex_pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b", "mask_with": "IP_PORT"},
            {"regex_pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,5}\b", "mask_with": "IP_PORT"},
            {"regex_pattern": r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", "mask_with": "MAC"},
            
            # Hash patterns
            {"regex_pattern": r"\b[a-fA-F0-9]{32}\b", "mask_with": "MD5"},
            {"regex_pattern": r"\b[a-fA-F0-9]{40}\b", "mask_with": "SHA1"},
            {"regex_pattern": r"\b[a-fA-F0-9]{64}\b", "mask_with": "SHA256"},
            
            # Time patterns
            {"regex_pattern": r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", "mask_with": "TIMESTAMP"},
            {"regex_pattern": r"\b\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}\b", "mask_with": "TIMESTAMP"},
            {"regex_pattern": r"\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", "mask_with": "SYSLOG_TIME"},
            
            # Identifiers
            {"regex_pattern": r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b", "mask_with": "UUID"},
            {"regex_pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "mask_with": "EMAIL"},
            {"regex_pattern": r"https?://[^\s<>\"{}|\\^`\[\]]+", "mask_with": "URL"},
            
            # File paths
            {"regex_pattern": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*", "mask_with": "WIN_PATH"},
            {"regex_pattern": r"\/(?:[^\/\0]+\/)*[^\/\0]*", "mask_with": "UNIX_PATH"},
            
            # Generic number masking (should be last)
            {"regex_pattern": r"\b\d+\b", "mask_with": "NUM"},
            {"regex_pattern": r"\b0x[0-9A-Fa-f]+\b", "mask_with": "HEX_NUM"},
        ]
        
        # Disable features we don't need
        config.profiling_enabled = False
        config.snapshot_enabled = False
        config.drain_max_sec_between_messages = None
        
        # Initialize the template miner with config
        self.template_miner = TemplateMiner(config=config)
        
        # Initialize common field extractors
        self._setup_field_extractors()
        
        logger.info("Drain3 engine initialized successfully")
    
    def _setup_field_extractors(self):
        """Setup regex patterns for common cybersecurity log fields"""
        self.field_extractors = {
            'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'timestamp': re.compile(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
            'syslog_timestamp': re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
            'port': re.compile(r':(\d{1,5})\b'),
            'mac': re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,7}'),
            'severity': re.compile(r'\b(critical|high|medium|low|info|debug|error|warning)\b', re.I),
            'action': re.compile(r'\b(allow|deny|block|permit|drop|reject|accept)\b', re.I),
            'protocol': re.compile(r'\b(tcp|udp|icmp|http|https|ftp|ssh|rdp|smb|dns)\b', re.I),
        }
    
    def detect_log_format(self, sample_lines: List[str]) -> Dict[str, Any]:
        """
        Automatically detect the log format from sample lines
        Returns detected format information
        """
        format_scores = {
            'cef': 0,
            'leef': 0,
            'json': 0,
            'syslog': 0,
            'csv': 0,
            'key_value': 0,
            'custom': 0
        }
        
        for line in sample_lines[:100]:  # Check first 100 lines
            line = line.strip()
            if not line:
                continue
                
            # CEF format detection
            if 'CEF:' in line or line.startswith('CEF:'):
                format_scores['cef'] += 1
                
            # LEEF format detection
            elif 'LEEF:' in line:
                format_scores['leef'] += 1
                
            # JSON format detection
            elif line.startswith('{') and line.endswith('}'):
                try:
                    json.loads(line)
                    format_scores['json'] += 1
                except:
                    pass
                    
            # Syslog format detection
            elif re.match(r'<\d+>', line) or re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
                format_scores['syslog'] += 1
                
            # CSV format detection
            elif ',' in line and len(line.split(',')) > 3:
                format_scores['csv'] += 1
                
            # Key-value format detection
            elif '=' in line and len(re.findall(r'\w+=[^=\s]+', line)) > 2:
                format_scores['key_value'] += 1
            
            else:
                format_scores['custom'] += 1
        
        # Determine the most likely format
        detected_format = max(format_scores, key=format_scores.get)
        confidence = format_scores[detected_format] / sum(format_scores.values()) if sum(format_scores.values()) > 0 else 0
        
        return {
            'format': detected_format,
            'confidence': confidence,
            'scores': format_scores,
            'sample_size': len(sample_lines)
        }
    
    def parse_log_line(self, log_line: str) -> Dict[str, Any]:
        """
        Parse a single log line using Drain3 and extract fields
        """
        if not log_line.strip():
            return None
            
        try:
            # Get the cluster template from Drain3
            result = self.template_miner.add_log_message(log_line)
            
            # Handle different return types from Drain3
            cluster_id = None
            cluster_size = None
            template_mined = None
            
            # Check if result is a dict or object
            if isinstance(result, dict):
                cluster_id = result.get('cluster_id', None)
                cluster_size = result.get('cluster_count', result.get('cluster_size', 0))
                template_mined = result.get('template_mined', '')
            elif hasattr(result, 'cluster_id'):
                cluster_id = result.cluster_id
                cluster_size = getattr(result, 'cluster_size', getattr(result, 'cluster_count', 0))
                template_mined = getattr(result, 'template_mined', '')
            else:
                # If result is just the cluster, get info directly
                logger.debug(f"Unexpected result type: {type(result)}")
                # Try to extract from the drain object directly
                if self.template_miner.drain.clusters:
                    # Find the cluster for this message
                    for cluster in self.template_miner.drain.clusters:
                        if log_line in [self.template_miner.drain.id_to_log_message.get(log_id, '') for log_id in cluster.log_template_ids]:
                            cluster_id = cluster.cluster_id
                            cluster_size = cluster.size
                            template_mined = cluster.get_template()
                            break
            
            # Extract structured fields
            extracted_fields = self._extract_fields(log_line)
            
            # Parse based on detected format
            parsed_data = self._parse_by_format(log_line, self.detected_format)
            
            return {
                'cluster_id': cluster_id,
                'cluster_size': cluster_size,
                'template_mined': template_mined,
                'extracted_fields': extracted_fields,
                'parsed_data': parsed_data,
                'raw_log': log_line,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error parsing log line: {str(e)}")
            logger.debug(f"Result type: {type(result) if 'result' in locals() else 'N/A'}")
            logger.debug(f"Result content: {result if 'result' in locals() else 'N/A'}")
            # Return a basic parsed result even on error
            return {
                'cluster_id': None,
                'cluster_size': 0,
                'template_mined': None,
                'extracted_fields': self._extract_fields(log_line),
                'parsed_data': {'format': 'unknown', 'content': log_line},
                'raw_log': log_line,
                'timestamp': datetime.utcnow().isoformat(),
                'parse_error': str(e)
            }
    
    def _extract_fields(self, log_line: str) -> Dict[str, List[str]]:
        """Extract common fields using regex patterns"""
        extracted = {}
        
        for field_name, pattern in self.field_extractors.items():
            matches = pattern.findall(log_line)
            if matches:
                extracted[field_name] = matches
                
        return extracted
    
    def _parse_by_format(self, log_line: str, format_type: str) -> Dict[str, Any]:
        """Parse log line based on detected format"""
        if not format_type:
            return {'format': 'unknown', 'content': log_line}
            
        if format_type == 'cef':
            return self._parse_cef(log_line)
        elif format_type == 'json':
            return self._parse_json(log_line)
        elif format_type == 'key_value':
            return self._parse_key_value(log_line)
        elif format_type == 'syslog':
            return self._parse_syslog(log_line)
        else:
            return {'format': 'custom', 'content': log_line}
    
    def _parse_cef(self, log_line: str) -> Dict[str, Any]:
        """Parse CEF format logs"""
        cef_pattern = re.compile(r'CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)')
        match = cef_pattern.search(log_line)
        
        if match:
            version, device_vendor, device_product, device_version, signature_id, name, severity, extension = match.groups()
            
            # Parse extension fields
            extension_fields = {}
            for kv in re.findall(r'(\w+)=([^=]+?)(?=\s+\w+=|$)', extension):
                extension_fields[kv[0]] = kv[1].strip()
            
            return {
                'format': 'cef',
                'version': version,
                'device_vendor': device_vendor,
                'device_product': device_product,
                'device_version': device_version,
                'signature_id': signature_id,
                'name': name,
                'severity': severity,
                'extension_fields': extension_fields
            }
        
        return {'format': 'cef', 'parse_error': 'Invalid CEF format'}
    
    def _parse_json(self, log_line: str) -> Dict[str, Any]:
        """Parse JSON format logs"""
        try:
            return json.loads(log_line)
        except json.JSONDecodeError as e:
            return {'format': 'json', 'parse_error': str(e)}
    
    def _parse_key_value(self, log_line: str) -> Dict[str, Any]:
        """Parse key-value format logs"""
        kv_pattern = re.compile(r'(\w+)=([^=\s]+)')
        fields = {}
        
        for match in kv_pattern.finditer(log_line):
            key, value = match.groups()
            fields[key] = value
        
        return {'format': 'key_value', 'fields': fields}
    
    def _parse_syslog(self, log_line: str) -> Dict[str, Any]:
        """Parse syslog format logs"""
        syslog_pattern = re.compile(
            r'(?:<(\d+)>)?'  # Priority
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\S+)\s+'  # Hostname
            r'(\S+?)(?:\[(\d+)\])?:\s*'  # Process[PID]
            r'(.*)'  # Message
        )
        
        match = syslog_pattern.match(log_line)
        if match:
            priority, timestamp, hostname, process, pid, message = match.groups()
            return {
                'format': 'syslog',
                'priority': priority,
                'timestamp': timestamp,
                'hostname': hostname,
                'process': process,
                'pid': pid,
                'message': message
            }
        
        return {'format': 'syslog', 'content': log_line}
    
    def get_cluster_patterns(self) -> List[Dict[str, Any]]:
        """Get all discovered cluster patterns"""
        clusters = []
        
        if not self.template_miner or not self.template_miner.drain:
            return clusters
            
        for cluster in self.template_miner.drain.clusters:
            clusters.append({
                'cluster_id': cluster.cluster_id,
                'size': cluster.size,
                'template': cluster.get_template(),
                'log_ids': list(cluster.log_template_ids) if hasattr(cluster, 'log_template_ids') else []
            })
        
        return sorted(clusters, key=lambda x: x['size'], reverse=True)
    
    def export_templates(self, output_file: str):
        """Export discovered templates to file"""
        templates = self.get_cluster_patterns()
        
        with open(output_file, 'w') as f:
            json.dump(templates, f, indent=2)
    
    def load_templates(self, template_file: str):
        """Load pre-trained templates"""
        # This would require additional implementation
        # to properly restore Drain3 state
        pass