"""
Drain3 configuration management
"""

import os
from configparser import ConfigParser

def create_default_config(output_path: str = "drain3.ini"):
    """Create default Drain3 configuration file"""
    
    config = ConfigParser()
    
    # Drain3 algorithm parameters
    config['DRAIN'] = {
        'sim_th': '0.4',  # Similarity threshold
        'depth': '4',     # Parse tree depth
        'max_children': '100',
        'max_clusters': '1000',
        'extra_delimiters': '[]<>():='  # Additional delimiters for parsing
    }
    
    # Preprocessing
    config['MASKING'] = {
        'masking': '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'masking_patterns': '''
            ([0-9a-fA-F]{32})
            ([0-9a-fA-F]{40})
            ([0-9a-fA-F]{64})
            (user|usr)=\S+
            (pass|pwd)=\S+
        '''
    }
    
    # Profiling
    config['PROFILING'] = {
        'enabled': 'False',
        'report_sec': '30'
    }
    
    # Snapshot
    config['SNAPSHOT'] = {
        'snapshot_interval_minutes': '10',
        'compress_state': 'True'
    }
    
    with open(output_path, 'w') as f:
        config.write(f)
    
    return output_path

# Create default config if not exists
if not os.path.exists('drain3.ini'):
    create_default_config()