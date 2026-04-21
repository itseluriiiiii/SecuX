import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Iterator, Optional, Tuple

from ..config import get_system_config, get_available_log_files, format_timestamp, SystemConfig
from .parsers.autodetect import AutoDetectParser
from .parsers.base import LogEntry
from .analyzers.anomaly import AnomalyDetector, Anomaly
from .output.json_formatter import JSONFormatter


class LogAnalysisAgent:
    
    def __init__(self, timeframe_hours: int = 24, severity_threshold: str = "LOW"):
        self.timeframe_hours = timeframe_hours
        self.severity_threshold = severity_threshold
        self.system_config = get_system_config()
        self.parser = AutoDetectParser()
        self.detector = AnomalyDetector()
        self.formatter = JSONFormatter()
        
        self._entries: List[LogEntry] = []
        self._logs_accessed: List[dict] = []
        self._access_errors: List[dict] = []
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._processing_duration: float = 0
        self._data_volume_mb: float = 0
    
    def run(
        self,
        log_paths: Optional[List[str]] = None,
        output_file: Optional[Path] = None,
        append: bool = False,
        show_summary: bool = True
    ) -> dict:
        
        start = time.time()
        
        if log_paths is None:
            available = get_available_log_files(self.system_config)
            log_paths = [l["path"] for l in available if l["status"] == "success"]
        
        self._logs_accessed = []
        self._access_errors = []
        self._entries = []
        total_size = 0
        
        for path in log_paths:
            if os.path.exists(path):
                size_mb = os.path.getsize(path) / (1024 * 1024)
                total_size += size_mb
                stat = os.stat(path)
                
                self._logs_accessed.append({
                    "path": path,
                    "size": f"{size_mb:.2f} MB",
                    "last_modified": format_timestamp(stat.st_mtime),
                    "status": "success"
                })
                
                entries = list(self.parser.parse(path))
                self._entries.extend(entries)
            else:
                self._logs_accessed.append({
                    "path": path,
                    "size": "0 MB",
                    "last_modified": "N/A",
                    "status": "failed"
                })
                self._access_errors.append({
                    "path": path,
                    "error": "file_not_found"
                })
        
        self._entries = self._filter_timeframe(self._entries)
        
        if self._entries:
            timestamps = [e.timestamp for e in self._entries if e.timestamp]
            if timestamps:
                self._start_time = min(timestamps)
                self._end_time = max(timestamps)
        
        findings = self.detector.analyze(self._entries, self.timeframe_hours)
        findings = self._filter_by_severity(findings)
        
        self._processing_duration = time.time() - start
        self._data_volume_mb = total_size
        
        result = self.formatter.format(
            agent_name="Log_Analysis_Agent",
            system_config=self.system_config,
            logs_accessed=self._logs_accessed,
            findings=findings,
            baseline_metrics=self.detector.get_baseline_metrics(),
            timeframe_start=self._start_time.isoformat() if self._start_time else None,
            timeframe_end=self._end_time.isoformat() if self._end_time else None,
            processing_duration=self._processing_duration,
            data_volume_mb=self._data_volume_mb,
            access_errors=self._access_errors
        )
        
        if output_file:
            self.formatter.save_to_file(result, output_file, append)
        
        if show_summary:
            self.formatter.print_summary(result)
        
        return result
    
    def run_incremental(
        self,
        log_paths: Optional[List[str]] = None,
        since: Optional[datetime] = None
    ) -> Tuple[List[LogEntry], List[Anomaly]]:
        
        if log_paths is None:
            available = get_available_log_files(self.system_config)
            log_paths = [l["path"] for l in available if l["status"] == "success"]
        
        new_entries = []
        
        for path in log_paths:
            if not os.path.exists(path):
                continue
            
            for entry in self.parser.parse(path):
                if since and entry.timestamp and entry.timestamp <= since:
                    continue
                new_entries.append(entry)
        
        findings = self.detector.analyze(new_entries, self.timeframe_hours)
        
        return new_entries, findings
    
    def _filter_timeframe(self, entries: List[LogEntry]) -> List[LogEntry]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.timeframe_hours)
        
        filtered = []
        for entry in entries:
            if entry.timestamp and entry.timestamp.tzinfo is None:
                entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)
            
            if entry.timestamp and entry.timestamp >= cutoff:
                filtered.append(entry)
        
        return filtered
    
    def _filter_by_severity(self, findings: List[Anomaly]) -> List[Anomaly]:
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        threshold_level = severity_order.get(self.severity_threshold, 0)
        
        return [
            f for f in findings
            if severity_order.get(f.severity, 0) >= threshold_level
        ]
    
    def get_entries(self) -> List[LogEntry]:
        return self._entries
    
    def get_system_info(self) -> SystemConfig:
        return self.system_config
