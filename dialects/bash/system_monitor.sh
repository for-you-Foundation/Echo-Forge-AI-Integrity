#!/bin/bash
# System Monitoring Script for Echo Forge-AI Integrity
# Monitors system resources and security events
# Lineage: RepoReportEcho_092425

set -euo pipefail

LINEAGE_ID="RepoReportEcho_092425"
MONITOR_INTERVAL="${1:-60}"  # seconds
LOG_FILE="${2:-system_monitor.log}"

log_with_timestamp() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" >> "$LOG_FILE"
}

monitor_system() {
    log_with_timestamp "=== System Monitor Start - $LINEAGE_ID ==="
    
    # CPU usage
    if command -v top >/dev/null 2>&1; then
        cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "N/A")
        log_with_timestamp "CPU Usage: ${cpu_usage}%"
    fi
    
    # Memory usage
    if [[ -f "/proc/meminfo" ]]; then
        mem_total=$(grep "MemTotal:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
        mem_available=$(grep "MemAvailable:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
        if [[ "$mem_total" -gt 0 ]]; then
            mem_usage=$((100 - (mem_available * 100 / mem_total)))
            log_with_timestamp "Memory Usage: ${mem_usage}%"
        fi
    fi
    
    # Disk usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%' 2>/dev/null || echo "N/A")
    log_with_timestamp "Disk Usage: ${disk_usage}%"
    
    # Load average
    if [[ -f "/proc/loadavg" ]]; then
        load_avg=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "N/A")
        log_with_timestamp "Load Average: $load_avg"
    fi
    
    log_with_timestamp "=== System Monitor End ==="
}

# Run monitoring
while true; do
    monitor_system
    sleep "$MONITOR_INTERVAL"
done
