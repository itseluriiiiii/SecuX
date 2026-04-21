from dataclasses import dataclass, field
from datetime import datetime, time
from typing import List, Dict, Optional
from collections import defaultdict


@dataclass
class Anomaly:
    finding_id: str
    type: str
    severity: str
    confidence: float
    description: str
    evidence: dict
    timestamp: str
    log_entries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "log_entries": self.log_entries
        }


class AnomalyDetector:
    
    BRUTE_FORCE_THRESHOLD = 5
    OFF_HOURS_START = time(22, 0)
    OFF_HOURS_END = time(6, 0)
    RAPID_REQUEST_THRESHOLD = 10
    LOG_GAP_THRESHOLD_SECONDS = 300
    ERROR_RATE_MULTIPLIER = 3.0
    
    def __init__(self):
        self.finding_counter = 0
        self.baseline_metrics = {
            "login_attempts_per_hour": defaultdict(int),
            "error_rate": defaultdict(int),
            "unique_ips": set(),
            "unique_users": set(),
            "total_events": 0,
            "hourly_events": defaultdict(int),
        }
    
    def analyze(self, entries: List, timeframe_hours: int = 24) -> List[Anomaly]:
        anomalies = []
        
        self._update_baseline(entries)
        
        brute_force = self._detect_brute_force(entries)
        anomalies.extend(brute_force)
        
        off_hours = self._detect_off_hours_activity(entries)
        anomalies.extend(off_hours)
        
        rapid_requests = self._detect_rapid_requests(entries)
        anomalies.extend(rapid_requests)
        
        error_spikes = self._detect_error_spikes(entries)
        anomalies.extend(error_spikes)
        
        privilege_escalation = self._detect_privilege_escalation(entries)
        anomalies.extend(privilege_escalation)
        
        log_gaps = self._detect_log_gaps(entries)
        anomalies.extend(log_gaps)
        
        unusual_auth = self._detect_unusual_auth_patterns(entries)
        anomalies.extend(unusual_auth)
        
        return anomalies
    
    def _update_baseline(self, entries: List) -> None:
        for entry in entries:
            self.baseline_metrics["total_events"] += 1
            
            if hasattr(entry, 'timestamp') and entry.timestamp:
                hour = entry.timestamp.hour
                self.baseline_metrics["hourly_events"][hour] += 1
            
            if entry.source_ip:
                self.baseline_metrics["unique_ips"].add(entry.source_ip)
            
            if entry.target_user:
                self.baseline_metrics["unique_users"].add(entry.target_user)
            
            if entry.event_type in ('login_failure', 'login_success'):
                if hasattr(entry, 'timestamp') and entry.timestamp:
                    self.baseline_metrics["login_attempts_per_hour"][entry.timestamp.hour] += 1
            
            if entry.level in ('Error', 'Warning'):
                if hasattr(entry, 'timestamp') and entry.timestamp:
                    self.baseline_metrics["error_rate"][entry.timestamp.hour] += 1
    
    def _detect_brute_force(self, entries: List) -> List[Anomaly]:
        anomalies = []
        login_failures = defaultdict(list)
        
        for entry in entries:
            if entry.event_type == 'login_failure' and entry.source_ip:
                login_failures[entry.source_ip].append(entry)
        
        for ip, failures in login_failures.items():
            if len(failures) >= self.BRUTE_FORCE_THRESHOLD:
                success_after = any(
                    e.event_type == 'login_success' and e.source_ip == ip
                    for e in entries
                    if e.timestamp >= failures[0].timestamp
                )
                
                if success_after:
                    severity = "CRITICAL"
                    confidence = min(0.95, 0.5 + (len(failures) * 0.05))
                else:
                    severity = "HIGH"
                    confidence = min(0.85, 0.4 + (len(failures) * 0.05))
                
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="brute_force_attempt",
                    severity=severity,
                    confidence=confidence,
                    description=f"Potential brute force attack detected from IP {ip}",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": len(failures),
                        "success_after_failures": success_after,
                        "source_ip": ip,
                        "target_user": failures[0].target_user,
                        "timeframe": self._format_timeframe(failures),
                        "event_count": len(failures),
                        "first_occurrence": failures[0].timestamp.isoformat() if failures else None,
                        "last_occurrence": failures[-1].timestamp.isoformat() if failures else None,
                    },
                    timestamp=failures[0].timestamp.isoformat() if failures else datetime.utcnow().isoformat(),
                    log_entries=[e.raw[:200] for e in failures[:5]]
                ))
        
        return anomalies
    
    def _detect_off_hours_activity(self, entries: List) -> List[Anomaly]:
        anomalies = []
        off_hours_entries = defaultdict(list)
        
        for entry in entries:
            if entry.timestamp and self._is_off_hours(entry.timestamp):
                key = entry.source_ip or "unknown"
                off_hours_entries[key].append(entry)
        
        for ip, ip_entries in off_hours_entries.items():
            if len(ip_entries) >= 3:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="off_hours_activity",
                    severity="MEDIUM",
                    confidence=0.7,
                    description=f"Multiple activities detected from {ip} during off-hours (10PM-6AM)",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": 0,
                        "success_after_failures": False,
                        "source_ip": ip,
                        "target_user": ip_entries[0].target_user,
                        "timeframe": f"{self._format_timeframe(ip_entries)} (off-hours)",
                        "event_count": len(ip_entries),
                        "first_occurrence": ip_entries[0].timestamp.isoformat(),
                        "last_occurrence": ip_entries[-1].timestamp.isoformat(),
                        "additional_context": f"Activity detected between {self.OFF_HOURS_START} and {self.OFF_HOURS_END}"
                    },
                    timestamp=ip_entries[0].timestamp.isoformat(),
                    log_entries=[e.raw[:200] for e in ip_entries[:3]]
                ))
        
        return anomalies
    
    def _detect_rapid_requests(self, entries: List) -> List[Anomaly]:
        anomalies = []
        request_times = defaultdict(list)
        
        for entry in entries:
            if entry.timestamp and entry.source_ip:
                key = entry.source_ip
                request_times[key].append(entry.timestamp)
        
        for ip, times in request_times.items():
            times.sort()
            for i in range(len(times) - self.RAPID_REQUEST_THRESHOLD):
                time_diff = (times[i + self.RAPID_REQUEST_THRESHOLD - 1] - times[i]).total_seconds()
                if time_diff < 1:
                    self.finding_counter += 1
                    anomalies.append(Anomaly(
                        finding_id=f"LA-{self.finding_counter:03d}",
                        type="rapid_requests",
                        severity="MEDIUM",
                        confidence=0.75,
                        description=f"High volume of requests from {ip} - possible automated attack",
                        evidence={
                            "log_source": "mixed",
                            "failed_attempts": 0,
                            "success_after_failures": False,
                            "source_ip": ip,
                            "target_user": None,
                            "timeframe": f"{time_diff:.2f} seconds",
                            "event_count": self.RAPID_REQUEST_THRESHOLD,
                            "first_occurrence": times[i].isoformat(),
                            "last_occurrence": times[i + self.RAPID_REQUEST_THRESHOLD - 1].isoformat(),
                            "additional_context": f"{self.RAPID_REQUEST_THRESHOLD}+ requests in under 1 second"
                        },
                        timestamp=times[i].isoformat(),
                        log_entries=[]
                    ))
                    break
        
        return anomalies
    
    def _detect_error_spikes(self, entries: List) -> List[Anomaly]:
        anomalies = []
        hourly_errors = defaultdict(int)
        hourly_total = defaultdict(int)
        
        for entry in entries:
            if entry.timestamp:
                hour = entry.timestamp.hour
                hourly_total[hour] += 1
                if entry.level in ('Error', 'Warning'):
                    hourly_errors[hour] += 1
        
        avg_error_rate = sum(hourly_errors.values()) / max(1, sum(hourly_total.values()))
        
        for hour, errors in hourly_errors.items():
            rate = errors / max(1, hourly_total[hour])
            if rate > avg_error_rate * self.ERROR_RATE_MULTIPLIER and errors > 10:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="error_rate_spike",
                    severity="MEDIUM",
                    confidence=0.65,
                    description=f"Elevated error rate detected during hour {hour:02d}:00",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": errors,
                        "success_after_failures": False,
                        "source_ip": None,
                        "target_user": None,
                        "timeframe": f"Hour {hour:02d}:00",
                        "event_count": errors,
                        "first_occurrence": f"{hour:02d}:00",
                        "last_occurrence": f"{hour:02d}:59",
                        "additional_context": f"Error rate: {rate:.1%} vs baseline: {avg_error_rate:.1%}"
                    },
                    timestamp=f"Hour {hour:02d}:00",
                    log_entries=[]
                ))
        
        return anomalies
    
    def _detect_privilege_escalation(self, entries: List) -> List[Anomaly]:
        anomalies = []
        
        for entry in entries:
            if entry.event_type == 'privilege_assign' or entry.event_type == 'privilege_escalation':
                if 'administrator' in entry.message.lower() or 'admin' in entry.message.lower():
                    severity = "CRITICAL"
                    confidence = 0.95
                else:
                    severity = "HIGH"
                    confidence = 0.8
                
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="privilege_escalation",
                    severity=severity,
                    confidence=confidence,
                    description=f"Privilege escalation detected for user {entry.target_user}",
                    evidence={
                        "log_source": entry.source,
                        "failed_attempts": 0,
                        "success_after_failures": False,
                        "source_ip": entry.source_ip,
                        "target_user": entry.target_user,
                        "timeframe": "single event",
                        "event_count": 1,
                        "first_occurrence": entry.timestamp.isoformat(),
                        "last_occurrence": entry.timestamp.isoformat(),
                        "additional_context": entry.message
                    },
                    timestamp=entry.timestamp.isoformat(),
                    log_entries=[entry.raw[:200]]
                ))
        
        return anomalies
    
    def _detect_log_gaps(self, entries: List) -> List[Anomaly]:
        anomalies = []
        
        if len(entries) < 2:
            return anomalies
        
        sorted_entries = sorted(entries, key=lambda e: e.timestamp)
        
        for i in range(len(sorted_entries) - 1):
            current = sorted_entries[i]
            next_entry = sorted_entries[i + 1]
            
            gap = (next_entry.timestamp - current.timestamp).total_seconds()
            
            if gap > self.LOG_GAP_THRESHOLD_SECONDS:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="log_gap",
                    severity="MEDIUM",
                    confidence=0.6,
                    description=f"Suspicious gap in logging: {gap/60:.1f} minutes without entries",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": 0,
                        "success_after_failures": False,
                        "source_ip": None,
                        "target_user": None,
                        "timeframe": f"{gap/60:.1f} minutes",
                        "event_count": 0,
                        "first_occurrence": current.timestamp.isoformat(),
                        "last_occurrence": next_entry.timestamp.isoformat(),
                        "additional_context": "Possible log tampering or service interruption"
                    },
                    timestamp=current.timestamp.isoformat(),
                    log_entries=[current.raw[:200], next_entry.raw[:200]]
                ))
        
        return anomalies
    
    def _detect_unusual_auth_patterns(self, entries: List) -> List[Anomaly]:
        anomalies = []
        
        login_events = [e for e in entries if e.event_type in ('login_success', 'login_failure')]
        if len(login_events) > 100:
            failed = sum(1 for e in login_events if e.event_type == 'login_failure')
            ratio = failed / len(login_events)
            
            if ratio > 0.8:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="high_failure_ratio",
                    severity="HIGH",
                    confidence=0.75,
                    description="Unusually high ratio of failed authentication attempts",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": failed,
                        "success_after_failures": True,
                        "source_ip": None,
                        "target_user": None,
                        "timeframe": "analysis period",
                        "event_count": len(login_events),
                        "first_occurrence": login_events[0].timestamp.isoformat() if login_events else None,
                        "last_occurrence": login_events[-1].timestamp.isoformat() if login_events else None,
                        "additional_context": f"Failure ratio: {ratio:.1%}"
                    },
                    timestamp=login_events[0].timestamp.isoformat() if login_events else datetime.utcnow().isoformat(),
                    log_entries=[]
                ))
        
        return anomalies
    
    def _is_off_hours(self, dt: datetime) -> bool:
        current_time = dt.time()
        
        if self.OFF_HOURS_START > self.OFF_HOURS_END:
            return current_time >= self.OFF_HOURS_START or current_time <= self.OFF_HOURS_END
        return self.OFF_HOURS_START <= current_time <= self.OFF_HOURS_END
    
    def _format_timeframe(self, entries: List) -> str:
        if not entries:
            return "unknown"
        
        first = entries[0].timestamp if hasattr(entries[0], 'timestamp') else entries[0].get('timestamp')
        last = entries[-1].timestamp if hasattr(entries[-1], 'timestamp') else entries[-1].get('timestamp')
        
        if first and last:
            duration = (last - first).total_seconds()
            if duration < 60:
                return f"{duration:.0f} seconds"
            elif duration < 3600:
                return f"{duration/60:.0f} minutes"
            else:
                return f"{duration/3600:.1f} hours"
        
        return "unknown"
    
    def get_baseline_metrics(self) -> dict:
        total_events = self.baseline_metrics["total_events"]
        total_login = sum(self.baseline_metrics["login_attempts_per_hour"].values())
        total_errors = sum(self.baseline_metrics["error_rate"].values())
        avg_login_per_hour = total_login / 24 if total_login else 0
        avg_error_rate = (total_errors / total_events * 100) if total_events > 0 else 0
        
        return {
            "average_login_attempts_per_hour": round(avg_login_per_hour, 2),
            "average_error_rate": round(avg_error_rate, 2),
            "unique_source_ips": len(self.baseline_metrics["unique_ips"]),
            "unique_users": len(self.baseline_metrics["unique_users"])
        }
