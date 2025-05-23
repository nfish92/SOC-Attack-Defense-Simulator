# logger.py
"""
Logger Module (Commented for Learning)
- Logs attack and defense events to JSONL or CSV
- Supports log rotation, filtering, console echo
- Allows replay of past logs for dashboard or investigation
"""

import json
import csv
import os
from datetime import datetime

class EventLogger:
    def __init__(
        self,
        output_dir="logs",              # Directory where logs will be saved
        log_format="jsonl",             # Supported: "jsonl" (line-delimited JSON) or "csv"
        echo_console=True,              # Whether to print log summaries to console
        filter_true_positive_only=False, # Only log true positives (skip benign/false positives)
        filter_failed_defense_only=False, # Only log failed defenses (skip successful ones)
        max_log_size_mb=5               # Log rotation trigger size (in megabytes)
    ):
        self.output_dir = output_dir
        self.log_format = log_format.lower()
        self.echo_console = echo_console
        self.filter_true_positive_only = filter_true_positive_only
        self.filter_failed_defense_only = filter_failed_defense_only
        self.max_log_size = max_log_size_mb * 1024 * 1024  # Convert MB to bytes

        # Ensure log folder exists
        os.makedirs(output_dir, exist_ok=True)

        # Define file paths
        self.attack_log_path = os.path.join(output_dir, f"attack_logs.{self.log_format}")
        self.defense_log_path = os.path.join(output_dir, f"defense_logs.{self.log_format}")

        # Set up CSV headers if needed
        if self.log_format == "csv":
            self._init_csv_headers()

    def _init_csv_headers(self):
        # Only write headers once if CSV files don't exist
        if not os.path.exists(self.attack_log_path):
            with open(self.attack_log_path, "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "attack_type", "source_ip", "destination_ip",
                    "severity", "is_logged", "is_true_positive", "benign_reason"
                ])
                writer.writeheader()

        if not os.path.exists(self.defense_log_path):
            with open(self.defense_log_path, "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "defense_timestamp", "defense_action", "defense_system", "defense_success",
                    "escalation_required", "urgent_escalation", "attack_event_id"
                ])
                writer.writeheader()

    def _rotate_log(self, path):
        # If log exceeds size threshold, rename and start fresh
        if os.path.exists(path) and os.path.getsize(path) > self.max_log_size:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_path = path.replace(f".{self.log_format}", f"_{timestamp}.{self.log_format}")
            os.rename(path, new_path)

    def _write_event(self, event, path):
        # Rotate log file if needed
        self._rotate_log(path)

        # Write event to file in selected format
        if self.log_format == "jsonl":
            with open(path, "a") as f:
                json.dump(event, f)
                f.write("\n")
        elif self.log_format == "csv":
            with open(path, "a", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=event.keys())
                writer.writerow(event)

        # Optional console output
        if self.echo_console:
            tag = event.get("attack_type") or event.get("defense_action") or "UNKNOWN"
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Logged: {tag}")

    def log_attack(self, event):
        # Skip if filtered and not a true positive
        if self.filter_true_positive_only and not event.get("is_true_positive", True):
            return
        self._write_event(event, self.attack_log_path)

    def log_defense(self, event):
        # Skip if filtered and defense succeeded
        if self.filter_failed_defense_only and event.get("defense_success", True):
            return
        self._write_event(event, self.defense_log_path)

    def load_log_replay(self, log_type="attack"):
        """
        Load previous logs from disk for replay or display.
        log_type: "attack" or "defense"
        """
        path = self.attack_log_path if log_type == "attack" else self.defense_log_path

        if self.log_format == "jsonl":
            with open(path) as f:
                return [json.loads(line) for line in f if line.strip()]

        elif self.log_format == "csv":
            with open(path) as f:
                reader = csv.DictReader(f)
                return [row for row in reader]

        return []
