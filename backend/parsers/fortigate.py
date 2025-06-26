from typing import Optional
from parsed_log import ParsedLog, LogType
from datetime import datetime
import re

def parse_fortigate(self, log_line: str, patterns) -> Optional[ParsedLog]:
        """Parse Fortigate logs based on decoder patterns"""
        # Try traffic pattern first
        match = re.search(patterns['v5_traffic'], log_line)
        if match:
            date_str = match.group(1)
            time_str = match.group(2)
            timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            
            parsed = ParsedLog(
                timestamp=timestamp,
                log_type=LogType.FORTIGATE,
                action=match.group(3),
                src_ip=match.group(4),
                dst_ip=match.group(5),
                bytes_sent=int(match.group(6)) if match.group(6) else 0,
                bytes_received=int(match.group(7)) if match.group(7) else 0,
                raw_log=log_line
            )
            
            # Extract additional fields from the full log line
            # Extract policy ID
            policy_match = re.search(r'policyid=(\d+)', log_line)
            if policy_match:
                parsed.policy_id = policy_match.group(1)
            
            # Extract source and destination countries
            src_country_match = re.search(r'srccountry="([^"]+)"', log_line)
            if src_country_match:
                parsed.src_country = src_country_match.group(1)
            
            dst_country_match = re.search(r'dstcountry="([^"]+)"', log_line)
            if dst_country_match:
                parsed.dst_country = dst_country_match.group(1)
            
            # Extract interfaces
            srcintf_match = re.search(r'srcintf="([^"]+)"', log_line)
            if srcintf_match:
                parsed.interface_in = srcintf_match.group(1)
            
            dstintf_match = re.search(r'dstintf="([^"]+)"', log_line)
            if dstintf_match:
                parsed.interface_out = dstintf_match.group(1)
            
            # Extract source and destination ports
            srcport_match = re.search(r'srcport=(\d+)', log_line)
            if srcport_match:
                parsed.src_port = int(srcport_match.group(1))
            
            dstport_match = re.search(r'dstport=(\d+)', log_line)
            if dstport_match:
                parsed.dst_port = int(dstport_match.group(1))
            
            # Extract protocol
            proto_match = re.search(r'proto=(\d+)', log_line)
            if proto_match:
                # Convert protocol number to name (6=TCP, 17=UDP, 1=ICMP)
                proto_num = int(proto_match.group(1))
                if proto_num == 6:
                    parsed.protocol = 'tcp'
                elif proto_num == 17:
                    parsed.protocol = 'udp'
                elif proto_num == 1:
                    parsed.protocol = 'icmp'
                else:
                    parsed.protocol = str(proto_num)
            
            return parsed
            
        # Try threat pattern
        threat_match = re.search(self.patterns[LogType.FORTIGATE]['v5_threat'], log_line)
        if threat_match:
            date_str = threat_match.group(1)
            time_str = threat_match.group(2)
            timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            
            parsed = ParsedLog(
                timestamp=timestamp,
                log_type=LogType.FORTIGATE,
                severity=threat_match.group(3),
                threat_name=threat_match.group(4),
                action='blocked',  # UTM logs are typically blocked threats
                raw_log=log_line
            )
            
            # Extract additional fields for UTM logs
            # Extract policy ID
            policy_match = re.search(r'policyid=(\d+)', log_line)
            if policy_match:
                parsed.policy_id = policy_match.group(1)
            
            # Extract source and destination IPs
            srcip_match = re.search(r'srcip=([^\s]+)', log_line)
            if srcip_match:
                parsed.src_ip = srcip_match.group(1)
            
            dstip_match = re.search(r'dstip=([^\s]+)', log_line)
            if dstip_match:
                parsed.dst_ip = dstip_match.group(1)
            
            # Extract source and destination ports
            srcport_match = re.search(r'srcport=(\d+)', log_line)
            if srcport_match:
                parsed.src_port = int(srcport_match.group(1))
            
            dstport_match = re.search(r'dstport=(\d+)', log_line)
            if dstport_match:
                parsed.dst_port = int(dstport_match.group(1))
            
            # Extract interfaces
            srcintf_match = re.search(r'srcintf="([^"]+)"', log_line)
            if srcintf_match:
                parsed.interface_in = srcintf_match.group(1)
            
            dstintf_match = re.search(r'dstintf="([^"]+)"', log_line)
            if dstintf_match:
                parsed.interface_out = dstintf_match.group(1)
            
            return parsed
            
        return None