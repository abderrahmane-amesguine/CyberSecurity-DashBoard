"""
Database configuration and functions
"""
import os
from supabase import create_client, Client
from typing import Dict, Any
import logging
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

supabase: Client = create_client(os.getenv("SUPABASE_URL"),os.getenv("SUPABASE_KEY"))
print("Supabase client initialized")

def store_parse_results(parse_result: Any) -> bool:
    """Store parsing results in database"""
    try:
        # Store main result
        result_data = {
            'file_id': parse_result.file_id,
            'file_name': parse_result.file_name,
            'parse_timestamp': parse_result.parse_timestamp.isoformat(),
            'detected_format': parse_result.detected_format,
            'format_confidence': parse_result.format_confidence,
            'total_lines': parse_result.total_lines,
            'parsed_lines': parse_result.parsed_lines,
            'error_lines': parse_result.error_lines,
            'success_rate': parse_result.success_rate,
            'unique_templates': parse_result.unique_templates,
            'threat_count': parse_result.threat_count,
            'critical_events': parse_result.critical_events,
            'security_summary': parse_result.security_summary
        }
        
        supabase.table('parse_results').insert(result_data).execute()
        
        # Store clusters
        for cluster in parse_result.clusters[:100]:  # Limit to 100
            cluster_data = {
                'file_id': parse_result.file_id,
                'cluster_id': cluster['cluster_id'],
                'template': cluster['template'],
                'occurrences': cluster['occurrences'],
                'category': cluster['category'],
                'severity': cluster['severity']
            }
            supabase.table('log_clusters').insert(cluster_data).execute()
        
        logger.info(f"Successfully stored parse results for file {parse_result.file_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error storing parse results: {e}")
        return False

def get_parse_results(file_id: str) -> Dict[str, Any]:
    """Retrieve parse results from database"""
    try:
        response = supabase.table('parse_results').select("*").eq('file_id', file_id).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        logger.error(f"Error retrieving parse results: {e}")
        return None