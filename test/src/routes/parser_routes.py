"""
Enhanced parser route for multiple security tools
"""

from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks, Form
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict
import tempfile
import os
from datetime import datetime
import logging

from ..parsers.drain3_parser import Drain3UniversalParser
from ..models.log_models import ParseResult
from ..utils.metrics_calculator import calculate_multi_tool_metrics, correlate_multi_tool_data
from ..config.database import store_parse_results

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/parser", tags=["Multi-Tool Log Parser"])

# Tool type mapping
TOOL_TYPE_MAPPING = {
    'f5': 'waf',
    'radware': 'waf',
    'fortinet_waf': 'waf',
    'sophos_fw': 'firewall',
    'paloalto': 'firewall',
    'cisco_asa': 'firewall',
    'checkpoint': 'firewall',
    'fortinet_fw': 'firewall',
    'sophos_av': 'antivirus',
    'symantec': 'antivirus',
    'kaspersky': 'antivirus',
    'nucleon': 'antivirus',
    'cybereason': 'antivirus',
    'nessus': 'vulnerability_scanner',
    'rapid7': 'vulnerability_scanner',
    'openvas': 'vulnerability_scanner',
    'acunetix': 'vulnerability_scanner',
    'owasp_zap': 'vulnerability_scanner',
    'ivanti': 'patch_management'
}

@router.post("/parse-tool")
async def parse_security_tool_logs(
    file: UploadFile = File(...),
    tool_name: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Parse logs from a specific security tool
    Returns tool-specific KPIs
    """
    try:
        # Validate tool name
        if tool_name.lower() not in TOOL_TYPE_MAPPING:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown tool: {tool_name}. Supported tools: {list(TOOL_TYPE_MAPPING.keys())}"
            )
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        content = await file.read()
        if len(content) > 200 * 1024 * 1024:  # 200MB limit
            raise HTTPException(status_code=413, detail="File too large. Maximum size is 200MB")
        
        # Initialize parser
        parser = Drain3UniversalParser()
        
        # Parse the logs
        parser.parse_bytes(content)
        
        if not parser.parsed_entries:
            raise HTTPException(
                status_code=400,
                detail=f"No valid log entries found. Errors: {parser.parse_errors[:5]}"
            )
        
        # Get tool type
        tool_type = TOOL_TYPE_MAPPING[tool_name.lower()]
        
        # Calculate tool-specific metrics
        metrics = calculate_multi_tool_metrics(parser.parsed_entries, tool_type)
        
        # Prepare response
        response = {
            "status": "success",
            "file_info": {
                "filename": file.filename,
                "tool_name": tool_name,
                "tool_type": tool_type,
                "total_lines": parser.metadata['total_lines'],
                "parsed_lines": parser.metadata['parsed_lines'],
                "success_rate": f"{parser.get_statistics()['success_rate']:.2f}%",
                "time_range": metrics['base_metrics']['time_range']
            },
            
            # Tool-specific KPIs
            "kpis": metrics['kpis'],
            
            # Base metrics
            "base_metrics": {
                "total_events": metrics['base_metrics']['total_events'],
                "severity_distribution": metrics['base_metrics']['severity_distribution'],
                "hourly_activity": metrics['base_metrics']['hourly_activity'],
                "unique_sources": metrics['base_metrics']['unique_sources'],
                "unique_destinations": metrics['base_metrics']['unique_destinations']
            },
            
            # Tool-specific metrics
            "specific_metrics": metrics['specific_metrics'],
            
            # Sample entries
            "sample_entries": parser.parsed_entries[:5],
            
            # Executive summary
            "summary": _generate_tool_summary(tool_name, tool_type, metrics)
        }
        
        # Store results in background
        background_tasks.add_task(
            store_parse_results,
            {
                'tool_name': tool_name,
                'tool_type': tool_type,
                'metrics': metrics,
                'timestamp': datetime.utcnow()
            }
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error parsing {tool_name} file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/parse-multiple")
async def parse_multiple_tools(
    files: List[UploadFile] = File(...),
    tool_names: str = Form(...)  # Comma-separated tool names
):
    """
    Parse logs from multiple security tools
    Returns correlated analysis
    """
    try:
        # Parse tool names
        tools = [t.strip() for t in tool_names.split(',')]
        
        if len(files) != len(tools):
            raise HTTPException(
                status_code=400,
                detail=f"Number of files ({len(files)}) must match number of tools ({len(tools)})"
            )
        
        # Process each file
        all_results = {}
        tool_data = {}
        
        for file, tool_name in zip(files, tools):
            # Validate tool
            print(f"Received {len(files)} files for parsing with tools: {tool_names}")
            if tool_name.lower() not in TOOL_TYPE_MAPPING:
                continue
                
            # Parse file
            content = await file.read()
            parser = Drain3UniversalParser()
            parser.parse_bytes(content)
            
            if parser.parsed_entries:
                tool_type = TOOL_TYPE_MAPPING[tool_name.lower()]
                metrics = calculate_multi_tool_metrics(parser.parsed_entries, tool_type)
                
                all_results[tool_name] = {
                    'filename': file.filename,
                    'metrics': metrics,
                    'parsed_entries': len(parser.parsed_entries)
                }
                tool_data[tool_name] = parser.parsed_entries
        
        # Correlate data across tools
        correlation_results = correlate_multi_tool_data(tool_data)
        
        # Generate unified response
        response = {
            "status": "success",
            "tools_processed": list(all_results.keys()),
            
            # Overall security posture
            "security_posture": {
                "unified_risk_score": correlation_results['unified_risk_score'],
                "multi_tool_detections": len(correlation_results['multi_tool_detections']),
                "total_events": sum(r['parsed_entries'] for r in all_results.values())
            },
            
            # Individual tool results
            "tool_results": {
                tool: {
                    "filename": result['filename'],
                    "kpis": result['metrics']['kpis'],
                    "summary": result['metrics']['base_metrics']
                }
                for tool, result in all_results.items()
            },
            
            # Correlation insights
            "correlation_insights": {
                "unified_threat_actors": dict(correlation_results['unified_threat_actors'].most_common(10)),
                "multi_tool_threats": correlation_results['multi_tool_detections'][:10]
            },
            
            # Aggregated KPIs
            "aggregated_kpis": _aggregate_kpis_across_tools(all_results)
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error parsing multiple files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/supported-tools")
async def get_supported_tools():
    """Get list of supported security tools"""
    tools_by_category = {
        "Web Application Firewalls (WAF)": [
            {"name": "F5 ASM", "key": "f5", "log_formats": ["CEF", "Custom"]},
            {"name": "Radware", "key": "radware", "log_formats": ["Custom"]},
            {"name": "Fortinet WAF", "key": "fortinet_waf", "log_formats": ["Syslog", "Custom"]}
        ],
        "Network Firewalls": [
            {"name": "Sophos Firewall", "key": "sophos_fw", "log_formats": ["Key-Value"]},
            {"name": "Palo Alto", "key": "paloalto", "log_formats": ["CSV", "Syslog"]},
            {"name": "Cisco ASA", "key": "cisco_asa", "log_formats": ["Syslog"]},
            {"name": "Check Point", "key": "checkpoint", "log_formats": ["CEF", "Custom"]},
            {"name": "Fortinet Firewall", "key": "fortinet_fw", "log_formats": ["Syslog", "Custom"]}
        ],
        "Antivirus/EDR": [
            {"name": "Sophos Antivirus", "key": "sophos_av", "log_formats": ["Custom"]},
            {"name": "Symantec", "key": "symantec", "log_formats": ["Custom"]},
            {"name": "Kaspersky", "key": "kaspersky", "log_formats": ["Custom"]},
            {"name": "Nucleon", "key": "nucleon", "log_formats": ["Custom"]},
            {"name": "Cybereason", "key": "cybereason", "log_formats": ["JSON"]}
        ],
        "Vulnerability Scanners": [
            {"name": "Nessus", "key": "nessus", "log_formats": ["CSV", "Custom"]},
            {"name": "Rapid7", "key": "rapid7", "log_formats": ["JSON", "CSV"]},
            {"name": "OpenVAS", "key": "openvas", "log_formats": ["XML", "Custom"]},
            {"name": "Acunetix", "key": "acunetix", "log_formats": ["JSON", "Custom"]},
            {"name": "OWASP ZAP", "key": "owasp_zap", "log_formats": ["JSON", "XML"]}
        ],
        "Patch Management": [
            {"name": "Ivanti", "key": "ivanti", "log_formats": ["Custom"]}
        ]
    }
    
    return {
        "categories": tools_by_category,
        "total_tools": sum(len(tools) for tools in tools_by_category.values()),
        "tool_keys": list(TOOL_TYPE_MAPPING.keys())
    }

@router.get("/kpi-definitions")
async def get_kpi_definitions():
    """Get definitions and explanations for all KPIs"""
    return {
        "kpis": {
            "taux_blocage": {
                "name": "Taux de blocage",
                "description": "Percentage of blocked connections/requests",
                "available_from": ["WAF", "Firewall"],
                "calculation": "blocked_events / total_events * 100"
            },
            "top_attack_types": {
                "name": "Top N des types d'attaques",
                "description": "Most common attack types detected",
                "available_from": ["WAF", "Firewall", "IDS/IPS"],
                "examples": ["SQL Injection", "XSS", "DDoS", "Port Scan"]
            },
            "volume_trafic_interface": {
                "name": "Volume de trafic par interface",
                "description": "Traffic volume breakdown by network interface",
                "available_from": ["Firewall"],
                "metrics": ["Bytes", "Packets", "Connections"]
            },
            "detections_temps_reel": {
                "name": "Détections en temps réel",
                "description": "Real-time threat detections in the last hour",
                "available_from": ["Antivirus", "EDR", "IDS/IPS"],
                "time_window": "1 hour"
            },
            "top_familles_malwares": {
                "name": "Top 10 des familles de malwares",
                "description": "Most detected malware families",
                "available_from": ["Antivirus", "EDR"],
                "examples": ["Ransomware", "Trojan", "Worm", "Adware"]
            },
            "connexions_bloquees": {
                "name": "Connexions bloquées",
                "description": "Total number of blocked network connections",
                "available_from": ["Firewall", "WAF"],
                "breakdown": ["By port", "By protocol", "By source"]
            },
            "bande_passante_consommee": {
                "name": "Bande passante consommée",
                "description": "Total bandwidth consumed",
                "available_from": ["Firewall", "WAF"],
                "units": ["Bytes", "MB", "GB", "TB"]
            },
            "vulnerabilites_critiques": {
                "name": "Vulnérabilités critiques non corrigées",
                "description": "Critical vulnerabilities discovered",
                "available_from": ["Vulnerability Scanner"],
                "severity": "CVSS >= 9.0"
            },
            "score_cvss_moyen": {
                "name": "Évolution du score CVSS moyen",
                "description": "Average CVSS score across all vulnerabilities",
                "available_from": ["Vulnerability Scanner"],
                "range": "0.0 - 10.0"
            },
            "actions_quarantaine_reussies": {
                "name": "Actions de quarantaine réussies",
                "description": "Success rate of quarantine actions",
                "available_from": ["Antivirus", "EDR"],
                "calculation": "successful_quarantines / total_quarantine_attempts * 100"
            }
        }
    }

# Helper functions

def _generate_tool_summary(tool_name: str, tool_type: str, metrics: Dict) -> Dict:
    """Generate executive summary for a specific tool"""
    base = metrics['base_metrics']
    specific = metrics['specific_metrics']
    kpis = metrics['kpis']
    
    summary = {
        "tool_category": tool_type.replace('_', ' ').title(),
        "total_events": base['total_events'],
        "time_span_hours": base['time_range'].get('duration_hours', 0),
        "key_findings": []
    }
    
    # Tool-specific findings
    if tool_type == 'waf':
        if 'blocking_rate' in specific:
            summary['key_findings'].append(f"Blocking rate: {specific['blocking_rate']:.2f}%")
        if 'sql_injection_attempts' in specific:
            summary['key_findings'].append(f"SQL injection attempts: {specific['sql_injection_attempts']}")
            
    elif tool_type == 'firewall':
        if 'connections_blocked' in specific:
            summary['key_findings'].append(f"Blocked connections: {specific['connections_blocked']}")
        if 'port_scans_detected' in specific:
            summary['key_findings'].append(f"Port scans detected: {specific['port_scans_detected']}")
            
    elif tool_type == 'antivirus':
        if 'quarantine_success_rate' in specific:
            summary['key_findings'].append(f"Quarantine success rate: {specific['quarantine_success_rate']:.2f}%")
        if 'malware_families' in specific:
            summary['key_findings'].append(f"Malware families detected: {len(specific['malware_families'])}")
            
    elif tool_type == 'vulnerability_scanner':
        if 'average_cvss' in specific:
            summary['key_findings'].append(f"Average CVSS score: {specific['average_cvss']:.2f}")
        critical = specific.get('vulnerabilities_by_severity', {}).get('Critical', 0)
        if critical > 0:
            summary['key_findings'].append(f"Critical vulnerabilities: {critical}")
            
    elif tool_type == 'patch_management':
        if 'success_rate' in specific:
            summary['key_findings'].append(f"Patch success rate: {specific['success_rate']:.2f}%")
    
    return summary

def _aggregate_kpis_across_tools(results: Dict) -> Dict:
    """Aggregate KPIs across multiple tools"""
    aggregated = {
        "network_security": {},
        "endpoint_security": {},
        "vulnerability_management": {},
        "overall_metrics": {}
    }
    
    # Calculate aggregated values
    total_events = sum(r['metrics']['base_metrics']['total_events'] for r in results.values())
    aggregated['overall_metrics']['total_events_analyzed'] = total_events
    
    # Add more aggregation logic as needed
    
    return aggregated