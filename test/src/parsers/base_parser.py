"""
Base parser class for all log parsers
Provides common functionality and interface
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class BaseLogParser(ABC):
    """Abstract base class for all log parsers"""
    
    def __init__(self):
        self.parsed_entries = []
        self.parse_errors = []
        self.metadata = {
            'parser_name': self.__class__.__name__,
            'parse_start': None,
            'parse_end': None,
            'total_lines': 0,
            'parsed_lines': 0,
            'error_lines': 0
        }
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        pass
    
    def parse_string(self, log_data: str) -> None:
        """Parse log data from string"""
        self.metadata['parse_start'] = datetime.utcnow()
        lines = log_data.strip().split('\n')
        self.metadata['total_lines'] = len(lines)
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                try:
                    entry = self.parse_line(line, line_num)
                    if entry:
                        self.parsed_entries.append(entry)
                        self.metadata['parsed_lines'] += 1
                except Exception as e:
                    self.parse_errors.append({
                        'line_number': line_num,
                        'line': line[:200],
                        'error': str(e)
                    })
                    self.metadata['error_lines'] += 1
        
        self.metadata['parse_end'] = datetime.utcnow()
    
    def parse_file(self, file_path: str) -> None:
        """Parse log file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.parse_string(f.read())
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {e}")
    
    def parse_bytes(self, log_bytes: bytes) -> None:
        """Parse log data from bytes"""
        try:
            log_data = log_bytes.decode('utf-8')
        except UnicodeDecodeError:
            log_data = log_bytes.decode('latin-1', errors='ignore')
        
        self.parse_string(log_data)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return {
            'metadata': self.metadata,
            'success_rate': (self.metadata['parsed_lines'] / self.metadata['total_lines'] * 100) 
                           if self.metadata['total_lines'] > 0 else 0,
            'error_rate': (self.metadata['error_lines'] / self.metadata['total_lines'] * 100) 
                         if self.metadata['total_lines'] > 0 else 0,
            'parse_duration': (self.metadata['parse_end'] - self.metadata['parse_start']).total_seconds() 
                            if self.metadata['parse_end'] and self.metadata['parse_start'] else 0
        }