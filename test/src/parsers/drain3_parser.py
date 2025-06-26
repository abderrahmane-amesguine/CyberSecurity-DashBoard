"""
Drain3-based universal parser
Integrates Drain3 engine with the base parser interface
"""

from typing import Dict, Any, Optional, List
from .base_parser import BaseLogParser
from ..core.drain3_engine import UniversalDrain3Engine
import logging

logger = logging.getLogger(__name__)

class Drain3UniversalParser(BaseLogParser):
    """Universal parser using Drain3 for any log format"""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.drain3_engine = UniversalDrain3Engine(config_path)
        print("Initializing Drain3UniversalParser with config:", config_path)
        self.format_detected = False
        self.log_format = None
        self.templates = {}
        
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse a single log line using Drain3"""
        try:
            # Auto-detect format on first lines
            if not self.format_detected and line_number <= 10:
                self._detect_format_from_sample()
            
            # Parse the line
            parsed = self.drain3_engine.parse_log_line(line)
            
            if parsed:
                # Add line metadata
                parsed['line_number'] = line_number
                parsed['parser'] = 'drain3_universal'
                
                # Extract cybersecurity-specific fields
                self._extract_security_fields(parsed)
                
                return parsed
                
        except Exception as e:
            logger.error(f"Error parsing line {line_number}: {e}")
            raise
            
    def _detect_format_from_sample(self):
        """Detect log format from parsed entries"""
        if len(self.parsed_entries) >= 5:
            sample_lines = [entry.get('raw_log', '') for entry in self.parsed_entries[:10]]
            format_info = self.drain3_engine.detect_log_format(sample_lines)
            self.log_format = format_info['format']
            self.drain3_engine.detected_format = self.log_format
            self.format_detected = True
            logger.info(f"Detected log format: {self.log_format} (confidence: {format_info['confidence']:.2f})")
    
    def _extract_security_fields(self, parsed_entry: Dict[str, Any]):
        """Extract cybersecurity-specific fields from parsed entry"""
        extracted = parsed_entry.get('extracted_fields', {})
        
        # Threat indicators
        if 'hash_md5' in extracted or 'hash_sha256' in extracted:
            parsed_entry['threat_indicators'] = {
                'md5': extracted.get('hash_md5', []),
                'sha256': extracted.get('hash_sha256', []),
                'ips': extracted.get('ip', []),
                'urls': extracted.get('url', [])
            }
        
        # Security actions and severity
        if 'action' in extracted:
            parsed_entry['security_action'] = extracted['action'][0] if extracted['action'] else None
        
        if 'severity' in extracted:
            parsed_entry['severity_level'] = extracted['severity'][0].lower() if extracted['severity'] else 'info'
        
        # Network information
        if 'ip' in extracted and len(extracted['ip']) >= 2:
            parsed_entry['network_flow'] = {
                'src_ip': extracted['ip'][0] if len(extracted['ip']) > 0 else None,
                'dst_ip': extracted['ip'][1] if len(extracted['ip']) > 1 else None,
                'protocol': extracted.get('protocol', [None])[0]
            }
    
    def get_cluster_analysis(self) -> Dict[str, Any]:
        """Get analysis of discovered log clusters"""
        clusters = self.drain3_engine.get_cluster_patterns()
        
        # Analyze clusters for security insights
        security_clusters = []
        for cluster in clusters:
            template = cluster['template']
            
            # Categorize cluster
            category = self._categorize_cluster(template)
            
            security_clusters.append({
                'cluster_id': cluster['cluster_id'],
                'template': template,
                'occurrences': cluster['size'],
                'category': category,
                'severity': self._estimate_severity(template, cluster['size'])
            })
        
        return {
            'total_clusters': len(clusters),
            'security_clusters': security_clusters,
            'format_detected': self.log_format,
            'parsing_stats': self.get_statistics()
        }
    
    def _categorize_cluster(self, template: str) -> str:
        """Categorize log cluster based on template"""
        template_lower = template.lower()
        
        if any(word in template_lower for word in ['attack', 'malware', 'virus', 'threat']):
            return 'threat_detection'
        elif any(word in template_lower for word in ['denied', 'blocked', 'rejected', 'dropped']):
            return 'access_control'
        elif any(word in template_lower for word in ['login', 'auth', 'credential', 'password']):
            return 'authentication'
        elif any(word in template_lower for word in ['error', 'fail', 'exception', 'critical']):
            return 'system_error'
        elif any(word in template_lower for word in ['connect', 'session', 'flow', 'traffic']):
            return 'network_activity'
        else:
            return 'general'
    
    def _estimate_severity(self, template: str, occurrences: int) -> str:
        """Estimate severity based on template and occurrence count"""
        template_lower = template.lower()
        
        # High severity indicators
        if any(word in template_lower for word in ['attack', 'malware', 'exploit', 'breach']):
            return 'critical'
        elif any(word in template_lower for word in ['unauthorized', 'violation', 'suspicious']):
            return 'high'
        elif occurrences > 1000:  # High volume might indicate issues
            return 'medium'
        else:
            return 'low'