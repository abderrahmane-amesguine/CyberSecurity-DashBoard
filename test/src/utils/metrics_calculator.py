"""
Multi-Tool Security Metrics Calculator
Handles KPI calculation for different security tool types
"""

from typing import List, Dict, Any, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)

class SecurityToolType(Enum):
    """Security tool categories"""
    WAF = "waf"  # F5, Radware, Fortinet WAF
    FIREWALL = "firewall"  # Sophos FW, Palo Alto, Cisco ASA, CheckPoint
    ANTIVIRUS = "antivirus"  # Sophos AV, Symantec, Kaspersky, Nucleon, Cybereason
    VULNERABILITY_SCANNER = "vulnerability_scanner"  # Nessus, Rapid7, OpenVAS, Acunetix, OWASP ZAP
    PATCH_MANAGEMENT = "patch_management"  # Ivanti
    UNKNOWN = "unknown"

class MultiToolMetricsCalculator:
    """Calculate KPIs from multiple security tool types"""
    
    def __init__(self):
        self.tool_patterns = self._initialize_tool_patterns()
        
    def _initialize_tool_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns to identify tool types from logs"""
        return {
            SecurityToolType.WAF: [
                'waf', 'web application firewall', 'modsecurity', 'f5 asm', 
                'radware', 'sql injection', 'xss', 'csrf', 'owasp'
            ],
            SecurityToolType.FIREWALL: [
                'firewall', 'asa-', 'checkpoint', 'palo alto', 'fortigate',
                'deny tcp', 'deny udp', 'blocked connection', 'interface outside'
            ],
            SecurityToolType.ANTIVIRUS: [
                'antivirus', 'malware', 'trojan', 'virus', 'kaspersky',
                'symantec', 'sophos av', 'quarantine', 'infected', 'cleaned'
            ],
            SecurityToolType.VULNERABILITY_SCANNER: [
                'vulnerability', 'cve-', 'cvss', 'nessus', 'openvas',
                'rapid7', 'acunetix', 'owasp zap', 'security scan'
            ],
            SecurityToolType.PATCH_MANAGEMENT: [
                'patch', 'update', 'ivanti', 'kb', 'hotfix', 'security update'
            ]
        }
    
    def detect_tool_type(self, entries: List[Dict[str, Any]]) -> SecurityToolType:
        """Detect the security tool type from log entries"""
        tool_scores = Counter()
        
        for entry in entries[:100]:  # Sample first 100 entries
            raw_log = entry.get('raw_log', '').lower()
            
            for tool_type, patterns in self.tool_patterns.items():
                for pattern in patterns:
                    if pattern in raw_log:
                        tool_scores[tool_type] += 1
        
        if tool_scores:
            return tool_scores.most_common(1)[0][0]
        return SecurityToolType.UNKNOWN
    
    def calculate_metrics_by_tool_type(self, entries: List[Dict[str, Any]], tool_type: Optional[SecurityToolType] = None) -> Dict[str, Any]:
        """Calculate metrics based on detected or specified tool type"""
        
        # Auto-detect tool type if not specified
        if not tool_type:
            tool_type = self.detect_tool_type(entries)
            
        logger.info(f"Calculating metrics for tool type: {tool_type.value}")
        
        # Base metrics applicable to all tools
        base_metrics = self._calculate_base_metrics(entries)
        
        # Tool-specific metrics
        if tool_type == SecurityToolType.WAF:
            specific_metrics = self._calculate_waf_metrics(entries)
        elif tool_type == SecurityToolType.FIREWALL:
            specific_metrics = self._calculate_firewall_metrics(entries)
        elif tool_type == SecurityToolType.ANTIVIRUS:
            specific_metrics = self._calculate_antivirus_metrics(entries)
        elif tool_type == SecurityToolType.VULNERABILITY_SCANNER:
            specific_metrics = self._calculate_vulnerability_metrics(entries)
        elif tool_type == SecurityToolType.PATCH_MANAGEMENT:
            specific_metrics = self._calculate_patch_metrics(entries)
        else:
            specific_metrics = {}
        
        return {
            'tool_type': tool_type.value,
            'base_metrics': base_metrics,
            'specific_metrics': specific_metrics,
            'kpis': self._calculate_unified_kpis(base_metrics, specific_metrics, tool_type)
        }
    
    def _calculate_base_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate base metrics common to all tools"""
        return {
            'total_events': len(entries),
            'time_range': self._get_time_range(entries),
            'severity_distribution': self._get_severity_distribution(entries),
            'hourly_activity': self._get_hourly_activity(entries),
            'unique_sources': self._count_unique_ips(entries, 'source'),
            'unique_destinations': self._count_unique_ips(entries, 'destination')
        }
    
    def _calculate_waf_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate WAF-specific metrics"""
        metrics = {
            'attack_types': Counter(),
            'blocked_requests': 0,
            'allowed_requests': 0,
            'rules_triggered': Counter(),
            'top_targeted_urls': Counter(),
            'sql_injection_attempts': 0,
            'xss_attempts': 0,
            'blocked_by_signature': Counter()
        }
        
        for entry in entries:
            raw_log = entry.get('raw_log', '').lower()
            
            # Count actions
            if any(word in raw_log for word in ['blocked', 'denied', 'rejected']):
                metrics['blocked_requests'] += 1
            elif any(word in raw_log for word in ['allowed', 'passed', 'permitted']):
                metrics['allowed_requests'] += 1
            
            # Detect attack types
            if 'sql' in raw_log and 'injection' in raw_log:
                metrics['attack_types']['SQL Injection'] += 1
                metrics['sql_injection_attempts'] += 1
            if 'xss' in raw_log or 'cross-site scripting' in raw_log:
                metrics['attack_types']['XSS'] += 1
                metrics['xss_attempts'] += 1
            if 'csrf' in raw_log:
                metrics['attack_types']['CSRF'] += 1
            if 'directory traversal' in raw_log or '../' in raw_log:
                metrics['attack_types']['Directory Traversal'] += 1
            if 'command injection' in raw_log:
                metrics['attack_types']['Command Injection'] += 1
            
            # Extract rule IDs
            rule_match = re.search(r'rule[_\s]?(?:id)?[:\s]?([^\s]+)', raw_log, re.I)
            if rule_match:
                metrics['rules_triggered'][rule_match.group(1)] += 1
            
            # Extract URLs
            url_match = re.search(r'(?:url|uri|path)[:\s]?([^\s]+)', raw_log, re.I)
            if url_match:
                metrics['top_targeted_urls'][url_match.group(1)] += 1
        
        # Calculate blocking rate
        total_requests = metrics['blocked_requests'] + metrics['allowed_requests']
        metrics['blocking_rate'] = (metrics['blocked_requests'] / total_requests * 100) if total_requests > 0 else 0
        
        return metrics
    
    def _calculate_firewall_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate firewall-specific metrics"""
        metrics = {
            'connections_blocked': 0,
            'connections_allowed': 0,
            'protocols': Counter(),
            'blocked_ports': Counter(),
            'interfaces': Counter(),
            'bytes_transferred': 0,
            'port_scans_detected': 0,
            'geo_blocks': Counter(),
            'rule_hits': Counter()
        }
        
        port_scan_sources = defaultdict(set)
        
        for entry in entries:
            raw_log = entry.get('raw_log', '')
            raw_log_lower = raw_log.lower()
            
            # Count actions
            if any(word in raw_log_lower for word in ['deny', 'denied', 'drop', 'reject', 'block']):
                metrics['connections_blocked'] += 1
                
                # Extract blocked port
                port_match = re.search(r'(?:dst|dpt|port)[:\s]?(\d+)', raw_log_lower)
                if port_match:
                    metrics['blocked_ports'][port_match.group(1)] += 1
                    
            elif any(word in raw_log_lower for word in ['allow', 'permit', 'accept', 'built']):
                metrics['connections_allowed'] += 1
            
            # Extract protocol
            proto_match = re.search(r'(?:proto|protocol)[:\s]?(\w+)', raw_log_lower)
            if proto_match:
                metrics['protocols'][proto_match.group(1).upper()] += 1
            elif 'tcp' in raw_log_lower:
                metrics['protocols']['TCP'] += 1
            elif 'udp' in raw_log_lower:
                metrics['protocols']['UDP'] += 1
            
            # Extract interface
            interface_match = re.search(r'(?:interface|int)[:\s]?(\w+)', raw_log_lower)
            if interface_match:
                metrics['interfaces'][interface_match.group(1)] += 1
            
            # Extract bytes
            bytes_match = re.search(r'bytes[:\s]?(\d+)', raw_log_lower)
            if bytes_match:
                metrics['bytes_transferred'] += int(bytes_match.group(1))
            
            # Detect port scans
            ips = entry.get('extracted_fields', {}).get('ip', [])
            if len(ips) >= 2 and port_match:
                port_scan_sources[ips[0]].add(port_match.group(1))
        
        # Identify port scanners
        for source, ports in port_scan_sources.items():
            if len(ports) > 10:
                metrics['port_scans_detected'] += 1
        
        # Calculate blocking rate
        total_connections = metrics['connections_blocked'] + metrics['connections_allowed']
        metrics['blocking_rate'] = (metrics['connections_blocked'] / total_connections * 100) if total_connections > 0 else 0
        
        return metrics
    
    def _calculate_antivirus_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate antivirus/EDR-specific metrics"""
        metrics = {
            'malware_families': Counter(),
            'detection_methods': Counter(),
            'actions_taken': Counter(),
            'infected_hosts': Counter(),
            'quarantine_success': 0,
            'quarantine_failed': 0,
            'cleaned_files': 0,
            'deleted_files': 0,
            'realtime_detections': 0,
            'signature_detections': 0,
            'heuristic_detections': 0,
            'top_threats': Counter()
        }
        
        for entry in entries:
            raw_log = entry.get('raw_log', '').lower()
            
            # Extract malware family/name
            malware_patterns = [
                r'(?:malware|virus|trojan|threat)[:\s]+([^\s,]+)',
                r'(?:detected|found)[:\s]+([^\s,]+)',
                r'threat[_\s]?name[:\s]+([^\s,]+)'
            ]
            
            for pattern in malware_patterns:
                match = re.search(pattern, raw_log, re.I)
                if match:
                    threat_name = match.group(1)
                    metrics['top_threats'][threat_name] += 1
                    
                    # Categorize malware family
                    if 'trojan' in threat_name.lower():
                        metrics['malware_families']['Trojan'] += 1
                    elif 'ransomware' in threat_name.lower():
                        metrics['malware_families']['Ransomware'] += 1
                    elif 'adware' in threat_name.lower():
                        metrics['malware_families']['Adware'] += 1
                    elif 'spyware' in threat_name.lower():
                        metrics['malware_families']['Spyware'] += 1
                    elif 'worm' in threat_name.lower():
                        metrics['malware_families']['Worm'] += 1
                    else:
                        metrics['malware_families']['Other'] += 1
                    break
            
            # Extract actions
            if 'quarantine' in raw_log:
                if 'success' in raw_log or 'completed' in raw_log:
                    metrics['quarantine_success'] += 1
                    metrics['actions_taken']['Quarantined'] += 1
                elif 'fail' in raw_log:
                    metrics['quarantine_failed'] += 1
            elif 'clean' in raw_log:
                metrics['cleaned_files'] += 1
                metrics['actions_taken']['Cleaned'] += 1
            elif 'delet' in raw_log:
                metrics['deleted_files'] += 1
                metrics['actions_taken']['Deleted'] += 1
            elif 'block' in raw_log:
                metrics['actions_taken']['Blocked'] += 1
            
            # Detection methods
            if 'signature' in raw_log:
                metrics['signature_detections'] += 1
                metrics['detection_methods']['Signature'] += 1
            elif 'heuristic' in raw_log or 'behavioral' in raw_log:
                metrics['heuristic_detections'] += 1
                metrics['detection_methods']['Heuristic'] += 1
            elif 'real-time' in raw_log or 'realtime' in raw_log:
                metrics['realtime_detections'] += 1
                metrics['detection_methods']['Real-time'] += 1
            
            # Extract infected host
            host_match = re.search(r'(?:host|computer|machine)[:\s]+([^\s,]+)', raw_log, re.I)
            if host_match:
                metrics['infected_hosts'][host_match.group(1)] += 1
        
        # Calculate quarantine success rate
        total_quarantine = metrics['quarantine_success'] + metrics['quarantine_failed']
        metrics['quarantine_success_rate'] = (metrics['quarantine_success'] / total_quarantine * 100) if total_quarantine > 0 else 0
        
        return metrics
    
    def _calculate_vulnerability_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate vulnerability scanner-specific metrics"""
        metrics = {
            'vulnerabilities_by_severity': Counter(),
            'cve_list': Counter(),
            'cvss_scores': [],
            'affected_hosts': Counter(),
            'vulnerability_categories': Counter(),
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'recurring_vulnerabilities': Counter(),
            'services_affected': Counter()
        }
        
        for entry in entries:
            raw_log = entry.get('raw_log', '')
            
            # Extract CVE
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', raw_log, re.I)
            for cve in cve_matches:
                metrics['cve_list'][cve] += 1
                metrics['recurring_vulnerabilities'][cve] += 1
            
            # Extract CVSS score
            cvss_match = re.search(r'cvss[:\s]+(\d+\.?\d*)', raw_log, re.I)
            if cvss_match:
                cvss_score = float(cvss_match.group(1))
                metrics['cvss_scores'].append(cvss_score)
                
                # Categorize by severity based on CVSS
                if cvss_score >= 9.0:
                    metrics['vulnerabilities_by_severity']['Critical'] += 1
                    metrics['critical_vulnerabilities'].append({
                        'cve': cve_matches[0] if cve_matches else 'Unknown',
                        'cvss': cvss_score,
                        'log': raw_log[:200]
                    })
                elif cvss_score >= 7.0:
                    metrics['vulnerabilities_by_severity']['High'] += 1
                    metrics['high_vulnerabilities'].append({
                        'cve': cve_matches[0] if cve_matches else 'Unknown',
                        'cvss': cvss_score,
                        'log': raw_log[:200]
                    })
                elif cvss_score >= 4.0:
                    metrics['vulnerabilities_by_severity']['Medium'] += 1
                else:
                    metrics['vulnerabilities_by_severity']['Low'] += 1
            
            # Extract severity if CVSS not available
            elif any(word in raw_log.lower() for word in ['critical', 'high', 'medium', 'low']):
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in raw_log.lower():
                        metrics['vulnerabilities_by_severity'][severity.capitalize()] += 1
                        break
            
            # Extract affected host
            host_patterns = [
                r'(?:host|target|ip)[:\s]+([^\s,]+)',
                r'(?:affected|vulnerable)[:\s]+([^\s,]+)'
            ]
            for pattern in host_patterns:
                host_match = re.search(pattern, raw_log, re.I)
                if host_match:
                    metrics['affected_hosts'][host_match.group(1)] += 1
                    break
            
            # Categorize vulnerability types
            vuln_categories = {
                'SQL Injection': ['sql injection', 'sqli'],
                'XSS': ['cross-site scripting', 'xss'],
                'Buffer Overflow': ['buffer overflow', 'stack overflow'],
                'Authentication': ['authentication', 'weak password', 'default credential'],
                'Encryption': ['weak encryption', 'ssl', 'tls', 'cipher'],
                'Configuration': ['misconfiguration', 'insecure configuration'],
                'Outdated Software': ['outdated', 'obsolete', 'unsupported version']
            }
            
            for category, keywords in vuln_categories.items():
                if any(keyword in raw_log.lower() for keyword in keywords):
                    metrics['vulnerability_categories'][category] += 1
        
        # Calculate average CVSS score
        if metrics['cvss_scores']:
            metrics['average_cvss'] = sum(metrics['cvss_scores']) / len(metrics['cvss_scores'])
        else:
            metrics['average_cvss'] = 0
        
        # Get top recurring vulnerabilities
        metrics['top_recurring'] = metrics['recurring_vulnerabilities'].most_common(10)
        
        return metrics
    
    def _calculate_patch_metrics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate patch management-specific metrics"""
        metrics = {
            'patches_deployed': 0,
            'patches_failed': 0,
            'patches_pending': 0,
            'systems_patched': Counter(),
            'patch_categories': Counter(),
            'critical_patches': 0,
            'security_patches': 0,
            'deployment_time': [],
            'success_rate': 0
        }
        
        for entry in entries:
            raw_log = entry.get('raw_log', '').lower()
            
            # Count patch deployment status
            if 'deployed' in raw_log or 'installed' in raw_log or 'success' in raw_log:
                metrics['patches_deployed'] += 1
            elif 'failed' in raw_log or 'error' in raw_log:
                metrics['patches_failed'] += 1
            elif 'pending' in raw_log or 'scheduled' in raw_log:
                metrics['patches_pending'] += 1
            
            # Extract system/host
            host_match = re.search(r'(?:host|system|computer)[:\s]+([^\s,]+)', raw_log, re.I)
            if host_match:
                metrics['systems_patched'][host_match.group(1)] += 1
            
            # Categorize patches
            if 'critical' in raw_log:
                metrics['critical_patches'] += 1
                metrics['patch_categories']['Critical'] += 1
            if 'security' in raw_log:
                metrics['security_patches'] += 1
                metrics['patch_categories']['Security'] += 1
            elif 'update' in raw_log:
                metrics['patch_categories']['Update'] += 1
            
            # Extract deployment time if available
            time_match = re.search(r'duration[:\s]+(\d+)', raw_log)
            if time_match:
                metrics['deployment_time'].append(int(time_match.group(1)))
        
        # Calculate success rate
        total_patches = metrics['patches_deployed'] + metrics['patches_failed']
        metrics['success_rate'] = (metrics['patches_deployed'] / total_patches * 100) if total_patches > 0 else 0
        
        # Calculate average deployment time
        if metrics['deployment_time']:
            metrics['avg_deployment_time'] = sum(metrics['deployment_time']) / len(metrics['deployment_time'])
        else:
            metrics['avg_deployment_time'] = 0
        
        return metrics
    
    def _calculate_unified_kpis(self, base_metrics: Dict, specific_metrics: Dict, tool_type: SecurityToolType) -> Dict[str, Any]:
        """Calculate unified KPIs based on tool type"""
        kpis = {}
        
        # Universal KPIs (available from most tools)
        kpis['total_events'] = base_metrics['total_events']
        kpis['time_range'] = base_metrics['time_range']
        
        # Tool-specific KPI mapping
        if tool_type == SecurityToolType.WAF:
            kpis['taux_blocage'] = {
                'value': f"{specific_metrics.get('blocking_rate', 0):.2f}%",
                'blocked': specific_metrics.get('blocked_requests', 0),
                'allowed': specific_metrics.get('allowed_requests', 0)
            }
            kpis['top_attack_types'] = dict(specific_metrics.get('attack_types', {}).most_common(10))
            kpis['performance_regles'] = dict(specific_metrics.get('rules_triggered', {}).most_common(10))
            
        elif tool_type == SecurityToolType.FIREWALL:
            kpis['taux_blocage'] = {
                'value': f"{specific_metrics.get('blocking_rate', 0):.2f}%",
                'blocked': specific_metrics.get('connections_blocked', 0),
                'allowed': specific_metrics.get('connections_allowed', 0)
            }
            kpis['connexions_bloquees'] = {
                'total': specific_metrics.get('connections_blocked', 0),
                'by_port': dict(specific_metrics.get('blocked_ports', {}).most_common(10)),
                'by_protocol': dict(specific_metrics.get('protocols', {}))
            }
            kpis['bande_passante_consommee'] = {
                'bytes': specific_metrics.get('bytes_transferred', 0),
                'mb': specific_metrics.get('bytes_transferred', 0) / (1024 * 1024),
                'gb': specific_metrics.get('bytes_transferred', 0) / (1024 * 1024 * 1024)
            }
            kpis['volume_trafic_interface'] = dict(specific_metrics.get('interfaces', {}))
            kpis['taux_couverture_scans'] = {
                'port_scans_detected': specific_metrics.get('port_scans_detected', 0)
            }
            
        elif tool_type == SecurityToolType.ANTIVIRUS:
            kpis['top_familles_malwares'] = dict(specific_metrics.get('malware_families', {}).most_common(10))
            kpis['detections_temps_reel'] = specific_metrics.get('realtime_detections', 0)
            kpis['actions_quarantaine_reussies'] = {
                'success_rate': f"{specific_metrics.get('quarantine_success_rate', 0):.2f}%",
                'successful': specific_metrics.get('quarantine_success', 0),
                'failed': specific_metrics.get('quarantine_failed', 0)
            }
            kpis['postes_infectes'] = len(specific_metrics.get('infected_hosts', {}))
            kpis['top_menaces'] = dict(specific_metrics.get('top_threats', {}).most_common(10))
            
        elif tool_type == SecurityToolType.VULNERABILITY_SCANNER:
            kpis['vulnerabilites_critiques'] = {
                'count': specific_metrics.get('vulnerabilities_by_severity', {}).get('Critical', 0),
                'list': specific_metrics.get('critical_vulnerabilities', [])[:10]
            }
            kpis['score_cvss_moyen'] = {
                'value': f"{specific_metrics.get('average_cvss', 0):.2f}",
                'total_vulns': len(specific_metrics.get('cvss_scores', []))
            }
            kpis['top_vulnerabilites_recurrentes'] = specific_metrics.get('top_recurring', [])
            kpis['distribution_severite'] = dict(specific_metrics.get('vulnerabilities_by_severity', {}))
            
        elif tool_type == SecurityToolType.PATCH_MANAGEMENT:
            kpis['taux_mise_a_jour'] = {
                'success_rate': f"{specific_metrics.get('success_rate', 0):.2f}%",
                'deployed': specific_metrics.get('patches_deployed', 0),
                'failed': specific_metrics.get('patches_failed', 0),
                'pending': specific_metrics.get('patches_pending', 0)
            }
            kpis['temps_moyen_remediation'] = {
                'minutes': specific_metrics.get('avg_deployment_time', 0)
            }
            kpis['systemes_patches'] = len(specific_metrics.get('systems_patched', {}))
            kpis['patches_critiques'] = specific_metrics.get('critical_patches', 0)
        
        return kpis
    
    # Helper methods (shared with base calculator)
    
    def _get_time_range(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get time range of log entries"""
        timestamps = []
        
        for entry in entries:
            # Try different timestamp locations
            timestamp_str = entry.get('timestamp')
            if not timestamp_str:
                # Try to extract from raw log
                raw_log = entry.get('raw_log', '')
                timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', raw_log)
                if timestamp_match:
                    timestamp_str = timestamp_match.group(0)
            
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    timestamps.append(timestamp)
                except:
                    pass
        
        if timestamps:
            return {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'duration_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600
            }
        
        return {'start': None, 'end': None, 'duration_hours': 0}
    
    def _get_severity_distribution(self, entries: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of events by severity"""
        severity_counts = Counter()
        
        severity_keywords = {
            'critical': ['critical', 'crit', 'emergency'],
            'high': ['high', 'error', 'err'],
            'medium': ['medium', 'warning', 'warn'],
            'low': ['low', 'info', 'informational'],
            'debug': ['debug', 'trace']
        }
        
        for entry in entries:
            severity = entry.get('severity_level')
            if severity:
                severity_counts[severity] += 1
            else:
                # Try to extract from raw log
                raw_log = entry.get('raw_log', '').lower()
                for sev_level, keywords in severity_keywords.items():
                    if any(keyword in raw_log for keyword in keywords):
                        severity_counts[sev_level] += 1
                        break
        
        return dict(severity_counts)
    
    def _get_hourly_activity(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get activity by hour"""
        hourly_counts = defaultdict(int)
        
        for entry in entries:
            raw_log = entry.get('raw_log', '')
            time_match = re.search(r'(\d{2}):(\d{2}):(\d{2})', raw_log)
            if time_match:
                hour = int(time_match.group(1))
                hourly_counts[hour] += 1
        
        return [{'hour': h, 'count': hourly_counts.get(h, 0)} for h in range(24)]
    
    def _count_unique_ips(self, entries: List[Dict[str, Any]], ip_type: str = 'source') -> int:
        """Count unique IPs (source or destination)"""
        unique_ips = set()
        
        for entry in entries:
            ips = entry.get('extracted_fields', {}).get('ip', [])
            if ip_type == 'source' and len(ips) > 0:
                unique_ips.add(ips[0])
            elif ip_type == 'destination' and len(ips) > 1:
                unique_ips.add(ips[1])
        
        return len(unique_ips)


def calculate_multi_tool_metrics(entries: List[Dict[str, Any]], tool_type: Optional[str] = None) -> Dict[str, Any]:
    """Main function to calculate metrics for any security tool"""
    calculator = MultiToolMetricsCalculator()
    
    # Convert string tool type to enum if provided
    if tool_type:
        try:
            tool_enum = SecurityToolType(tool_type.lower())
        except ValueError:
            tool_enum = None
    else:
        tool_enum = None
    
    return calculator.calculate_metrics_by_tool_type(entries, tool_enum)


# Correlation function for multiple tools
def correlate_multi_tool_data(tool_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Correlate data from multiple security tools"""
    correlation_results = {
        'unified_threat_actors': Counter(),
        'multi_tool_detections': [],
        'timeline_correlation': [],
        'unified_risk_score': 0,
        'comprehensive_kpis': {}
    }
    
    # Collect all unique threat IPs across tools
    all_threat_ips = set()
    for tool_name, entries in tool_data.items():
        for entry in entries:
            ips = entry.get('extracted_fields', {}).get('ip', [])
            if ips and entry.get('severity_level') in ['critical', 'high']:
                all_threat_ips.add(ips[0])
                correlation_results['unified_threat_actors'][ips[0]] += 1
    
    # Find threats detected by multiple tools
    for ip, count in correlation_results['unified_threat_actors'].items():
        if count > 1:
            correlation_results['multi_tool_detections'].append({
                'threat_ip': ip,
                'detection_count': count,
                'detected_by': [tool for tool in tool_data.keys()]
            })
    
    # Calculate unified risk score
    total_critical_events = 0
    total_high_events = 0
    
    for tool_name, entries in tool_data.items():
        calculator = MultiToolMetricsCalculator()
        tool_type = calculator.detect_tool_type(entries)
        metrics = calculator.calculate_metrics_by_tool_type(entries, tool_type)
        
        # Add to comprehensive KPIs
        correlation_results['comprehensive_kpis'][tool_name] = metrics['kpis']
        
        # Count critical events
        severity_dist = metrics['base_metrics'].get('severity_distribution', {})
        total_critical_events += severity_dist.get('critical', 0)
        total_high_events += severity_dist.get('high', 0)
    
    # Calculate risk score (0-100)
    risk_score = min(100, (total_critical_events * 10) + (total_high_events * 5))
    correlation_results['unified_risk_score'] = risk_score
    
    return correlation_results