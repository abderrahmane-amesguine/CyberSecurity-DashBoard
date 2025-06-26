from typing import Dict, List
from collections import defaultdict
from parsed_log import ParsedLog, LogType

class SecurityKPICalculator:
    """
    Calculate security KPIs based on parsed logs
    Reference: NIST Cybersecurity Framework, ISO 27001
    """
    
    def __init__(self):
        self.logs: List[ParsedLog] = []
        
    def add_logs(self, logs: List[ParsedLog]):
        """Add parsed logs for analysis"""
        self.logs.extend(logs)
        print(self.logs)  # Debugging line to check logs added
        
    def calculate_strategic_kpis(self) -> Dict:
        """
        Calculate strategic KPIs
        Based on: NIST CSF risk assessment methodology
        """
        kpis = {}
        
        # Cyber Risk Score (0-100)
        # Formula based on FAIR (Factor Analysis of Information Risk) methodology
        threat_count = sum(1 for log in self.logs if log.action in ['deny', 'block', 'detected'])
        total_events = len(self.logs)
        
        if total_events > 0:
            threat_ratio = threat_count / total_events
            # Risk score calculation: Higher threat ratio = higher risk
            # Adding weight for severity
            severity_weight = sum(
                3 if log.severity == 'critical' else
                2 if log.severity == 'high' else
                1 if log.severity == 'medium' else 0
                for log in self.logs if log.severity
            ) / max(total_events, 1)
            
            kpis['cyber_risk_score'] = min(100, int((threat_ratio * 70) + (severity_weight * 30)))
        else:
            kpis['cyber_risk_score'] = 0
            
        # Threat Landscape Evolution
        # Group threats by time period
        threat_timeline = defaultdict(int)
        for log in self.logs:
            if log.threat_name:
                month_key = log.timestamp.strftime("%Y-%m")
                threat_timeline[month_key] += 1
                
        kpis['threat_evolution'] = dict(threat_timeline)
        
        return kpis
    
    def calculate_managerial_kpis(self) -> Dict:
        """
        Calculate managerial KPIs
        Based on: ISO 27001 performance measurement requirements
        """
        kpis = {}
        
        # Geographic coverage (from Fortigate/Palo Alto country codes)
        geo_threats = defaultdict(int)
        for log in self.logs:
            if log.src_country:
                geo_threats[log.src_country] += 1
            # Also count destination countries for comprehensive coverage
            if log.dst_country:
                geo_threats[log.dst_country] += 1
                
        kpis['geographic_coverage'] = dict(geo_threats)
        
        # Mean Time To Detection (MTTD)
        # Note: Real MTTD requires correlation with actual attack start time
        # Using time between similar events as proxy
        detection_times = []
        threat_first_seen = {}
        
        for log in self.logs:
            if log.threat_name:
                if log.threat_name not in threat_first_seen:
                    threat_first_seen[log.threat_name] = log.timestamp
                else:
                    time_diff = (log.timestamp - threat_first_seen[log.threat_name]).total_seconds()
                    if time_diff > 0:
                        detection_times.append(time_diff)
                        
        if detection_times:
            kpis['mttd_seconds'] = sum(detection_times) / len(detection_times)
        else:
            kpis['mttd_seconds'] = 0
            
        # Coverage percentage (based on unique IPs seen)
        unique_ips = set()
        for log in self.logs:
            if log.src_ip:
                unique_ips.add(log.src_ip)
            if log.dst_ip:
                unique_ips.add(log.dst_ip)
                
        # Assuming organization has declared asset count (would come from CMDB)
        # Using proxy calculation
        kpis['asset_coverage_count'] = len(unique_ips)
        
        return kpis

    def calculate_operational_kpis(self) -> Dict:
        """
        Calculate operational KPIs
        Based on: Real-time security monitoring best practices
        """
        kpis = {}
        
        # Real-time blocking rate
        # Count all security actions (deny, block, drop, alert, etc.)
        blocked_count = sum(1 for log in self.logs if log.action and log.action.lower() in ['deny', 'block', 'drop', 'blocked'])
        # Count all traffic logs that could potentially be blocked
        total_traffic = len([log for log in self.logs if log.log_type in [LogType.CISCO_ASA, LogType.FORTIGATE, LogType.PALOALTO] and log.action])
        
        if total_traffic > 0:
            kpis['blocking_rate_percent'] = (blocked_count / total_traffic) * 100
        else:
            kpis['blocking_rate_percent'] = 0
            
        # Performance by policy (Fortigate/Palo Alto)
        policy_performance = defaultdict(lambda: {'total': 0, 'blocked': 0})
        for log in self.logs:
            if log.policy_id:
                policy_performance[log.policy_id]['total'] += 1
                if log.action and log.action.lower() in ['deny', 'block', 'drop', 'blocked']:
                    policy_performance[log.policy_id]['blocked'] += 1
                    
        kpis['policy_effectiveness'] = {
            policy: {
                'total_events': stats['total'],
                'blocked_events': stats['blocked'],
                'effectiveness_percent': (stats['blocked'] / stats['total'] * 100) if stats['total'] > 0 else 0
            }
            for policy, stats in policy_performance.items()
        }
        
        # Traffic volume by interface
        interface_traffic = defaultdict(lambda: {'in_bytes': 0, 'out_bytes': 0})
        for log in self.logs:
            if log.interface_in and log.bytes_received:
                interface_traffic[log.interface_in]['in_bytes'] += log.bytes_received
            if log.interface_out and log.bytes_sent:
                interface_traffic[log.interface_out]['out_bytes'] += log.bytes_sent
                
        kpis['interface_traffic'] = dict(interface_traffic)
        
        # Malware detections per hour
        malware_timeline = defaultdict(int)
        for log in self.logs:
            if log.log_type in [LogType.SOPHOS, LogType.KASPERSKY, LogType.SYMANTEC] and log.threat_name:
                hour_key = log.timestamp.strftime("%Y-%m-%d %H:00")
                malware_timeline[hour_key] += 1
                
        kpis['malware_detections_hourly'] = dict(malware_timeline)
        
        # Bandwidth analysis
        total_sent = sum(log.bytes_sent for log in self.logs if log.bytes_sent)
        total_received = sum(log.bytes_received for log in self.logs if log.bytes_received)
        
        kpis['bandwidth_analysis'] = {
            'total_bytes_sent': total_sent,
            'total_bytes_received': total_received,
            'total_bytes': total_sent + total_received
        }
        
        # Geo-location threats
        threat_sources = defaultdict(int)
        threat_destinations = defaultdict(int)
        
        for log in self.logs:
            # Only count logs that represent actual threats/security events
            if log.action and log.action.lower() in ['deny', 'block', 'detected', 'alert', 'blocked']:
                if log.src_country:
                    threat_sources[log.src_country] += 1
                if log.dst_country:
                    threat_destinations[log.dst_country] += 1
                    
        kpis['threat_geography'] = {
            'source_countries': dict(threat_sources),
            'destination_countries': dict(threat_destinations)
        }
        
        return kpis