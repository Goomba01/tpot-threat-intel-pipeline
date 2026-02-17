"""
core/database.py

SQLite storage layer for the T-Pot threat intelligence pipeline.

Schema:
  events      - Raw honeypot events (one row per event)
  enrichments - IP enrichment data from threat intel APIs (one row per IP)

Design decisions:
  - SQLite is used for portability (no server needed, easily shared/backed up)
  - IPs are the primary key for enrichments - one enrichment row per IP
  - Events reference IPs but are stored separately to avoid denormalisation
  - JSON blobs store raw event data for future reprocessing
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional

logger = logging.getLogger("tpot_pipeline.database")


class ThreatDatabase:
    """SQLite-backed store for honeypot events and IP enrichment data."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row   # dict-like rows
            self._conn.execute("PRAGMA journal_mode=WAL")  # concurrent writes
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialise(self):
        """Create tables if they don't exist. Safe to call on existing DBs."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip          TEXT    NOT NULL,
                src_port        INTEGER,
                dst_port        INTEGER,
                protocol        TEXT,
                service         TEXT,
                timestamp       TEXT,
                event_type      TEXT,
                username        TEXT,
                password        TEXT,
                command         TEXT,
                url             TEXT,
                filename        TEXT,
                sha256          TEXT,
                alert_sig       TEXT,
                alert_cat       TEXT,
                severity        INTEGER,
                session         TEXT,
                source_file     TEXT,
                raw_json        TEXT,
                ingested_at     TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS enrichments (
                ip              TEXT PRIMARY KEY,
                enriched_at     TEXT,

                -- Geolocation (ip-api.com)
                country         TEXT,
                country_code    TEXT,
                region          TEXT,
                city            TEXT,
                latitude        REAL,
                longitude       REAL,
                timezone        TEXT,
                isp             TEXT,
                org             TEXT,
                asn             TEXT,
                asn_name        TEXT,

                -- AbuseIPDB
                abuse_score     INTEGER DEFAULT 0,
                abuse_reports   INTEGER DEFAULT 0,
                abuse_last_seen TEXT,
                usage_type      TEXT,
                domain          TEXT,
                is_tor          INTEGER DEFAULT 0,
                is_public       INTEGER DEFAULT 1,

                -- VirusTotal
                vt_malicious    INTEGER DEFAULT 0,
                vt_suspicious   INTEGER DEFAULT 0,
                vt_harmless     INTEGER DEFAULT 0,
                vt_undetected   INTEGER DEFAULT 0,
                vt_last_analysis TEXT,

                -- Shodan
                open_ports      TEXT,
                shodan_tags     TEXT,
                vuln_cves       TEXT,
                vuln_count      INTEGER DEFAULT 0,
                hostnames       TEXT,
                shodan_updated  TEXT,

                -- Derived
                threat_level    TEXT DEFAULT 'UNKNOWN'
            );

            -- Indexes for common queries
            CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_service  ON events(service);
            CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_enrichments_score ON enrichments(abuse_score DESC);
        """)
        conn.commit()
        logger.debug("Database initialised: %s", self.db_path)

    # ------------------------------------------------------------------
    # Event storage
    # ------------------------------------------------------------------

    def insert_event(self, event: dict):
        """Insert a single honeypot event. Skips on duplicate (same IP+ts+type)."""
        conn = self._get_conn()
        fields = [
            "src_ip", "src_port", "dst_port", "protocol", "service",
            "timestamp", "event_type", "username", "password",
            "command", "url", "filename", "sha256",
            "alert_sig", "alert_cat", "severity", "session",
            "source_file", "raw_json"
        ]
        values = [event.get(f) for f in fields]
        placeholders = ", ".join("?" * len(fields))
        cols = ", ".join(fields)

        try:
            conn.execute(
                f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})",
                values
            )
            conn.commit()
        except sqlite3.Error as e:
            logger.error("DB insert failed: %s | event: %s", e, str(event)[:100])

    def insert_events_bulk(self, events: List[dict]):
        """Bulk insert for better performance when parsing large files."""
        conn = self._get_conn()
        fields = [
            "src_ip", "src_port", "dst_port", "protocol", "service",
            "timestamp", "event_type", "username", "password",
            "command", "url", "filename", "sha256",
            "alert_sig", "alert_cat", "severity", "session",
            "source_file", "raw_json"
        ]
        rows = [[e.get(f) for f in fields] for e in events if e.get("src_ip")]
        placeholders = ", ".join("?" * len(fields))
        cols = ", ".join(fields)
        try:
            conn.executemany(
                f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})",
                rows
            )
            conn.commit()
        except sqlite3.Error as e:
            logger.error("Bulk insert failed: %s", e)

    # ------------------------------------------------------------------
    # Enrichment storage
    # ------------------------------------------------------------------

    def upsert_enrichment(self, ip: str, data: dict):
        """
        Insert or update enrichment for an IP.
        Also calculates and stores derived threat_level.
        """
        from core.enricher import IPEnricher
        data["threat_level"] = IPEnricher.classify_threat_level(data)
        data["ip"] = ip

        fields = [
            "ip", "enriched_at", "country", "country_code", "region", "city",
            "latitude", "longitude", "timezone", "isp", "org", "asn", "asn_name",
            "abuse_score", "abuse_reports", "abuse_last_seen", "usage_type", "domain",
            "is_tor", "is_public", "vt_malicious", "vt_suspicious", "vt_harmless",
            "vt_undetected", "vt_last_analysis", "open_ports", "shodan_tags",
            "vuln_cves", "vuln_count", "hostnames", "shodan_updated", "threat_level"
        ]
        values = [data.get(f) for f in fields]
        placeholders = ", ".join("?" * len(fields))
        cols = ", ".join(fields)
        updates = ", ".join(f"{f}=excluded.{f}" for f in fields if f != "ip")

        try:
            self._get_conn().execute(
                f"""INSERT INTO enrichments ({cols}) VALUES ({placeholders})
                    ON CONFLICT(ip) DO UPDATE SET {updates}""",
                values
            )
            self._get_conn().commit()
            level = data.get("threat_level", "UNKNOWN")
            logger.debug("    Stored enrichment for %s -> threat_level=%s", ip, level)
        except sqlite3.Error as e:
            logger.error("Enrichment upsert failed for %s: %s", ip, e)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_unenriched_ips(self, cache_ttl_days: int = 7) -> List[str]:
        """
        Return all unique source IPs from events that:
          a) have no enrichment record yet, OR
          b) have a stale enrichment (older than cache_ttl_days)
        """
        cutoff = (datetime.utcnow() - timedelta(days=cache_ttl_days)).isoformat()
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT DISTINCT e.src_ip
            FROM events e
            LEFT JOIN enrichments en ON e.src_ip = en.ip
            WHERE en.ip IS NULL
               OR en.enriched_at < ?
            ORDER BY e.src_ip
        """, (cutoff,)).fetchall()
        return [r["src_ip"] for r in rows]

    def count_cached_ips(self, cache_ttl_days: int = 7) -> int:
        """Count IPs with fresh (non-stale) enrichment."""
        cutoff = (datetime.utcnow() - timedelta(days=cache_ttl_days)).isoformat()
        row = self._get_conn().execute(
            "SELECT COUNT(*) FROM enrichments WHERE enriched_at >= ?", (cutoff,)
        ).fetchone()
        return row[0] if row else 0

    def get_top_attackers(self, limit: int = 20) -> List[dict]:
        """Return top attacking IPs by event count, joined with enrichment data."""
        rows = self._get_conn().execute("""
            SELECT
                e.src_ip,
                COUNT(*) as event_count,
                COUNT(DISTINCT e.event_type) as event_types,
                MAX(e.timestamp) as last_seen,
                en.country, en.city, en.isp, en.asn_name,
                en.abuse_score, en.abuse_reports,
                en.vt_malicious, en.is_tor,
                en.threat_level, en.open_ports, en.shodan_tags
            FROM events e
            LEFT JOIN enrichments en ON e.src_ip = en.ip
            GROUP BY e.src_ip
            ORDER BY event_count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_events_for_ip(self, ip: str) -> List[dict]:
        """Get all events for a specific source IP, ordered by timestamp."""
        rows = self._get_conn().execute(
            "SELECT * FROM events WHERE src_ip = ? ORDER BY timestamp ASC", (ip,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_credential_pairs(self, limit: int = 50) -> List[dict]:
        """Most attempted username/password combinations."""
        rows = self._get_conn().execute("""
            SELECT username, password, COUNT(*) as attempts,
                   COUNT(DISTINCT src_ip) as unique_ips
            FROM events
            WHERE username IS NOT NULL AND password IS NOT NULL
            GROUP BY username, password
            ORDER BY attempts DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_attack_summary_by_service(self) -> List[dict]:
        """Event counts broken down by honeypot service."""
        rows = self._get_conn().execute("""
            SELECT service,
                   COUNT(*) as events,
                   COUNT(DISTINCT src_ip) as unique_ips,
                   COUNT(DISTINCT event_type) as event_types
            FROM events
            GROUP BY service
            ORDER BY events DESC
        """).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats / reporting
    # ------------------------------------------------------------------

    def print_stats(self):
        """Print a human-readable summary of database contents."""
        conn = self._get_conn()

        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_ips    = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
        enriched_ips = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        crit_ips     = conn.execute("SELECT COUNT(*) FROM enrichments WHERE threat_level='CRITICAL'").fetchone()[0]
        high_ips     = conn.execute("SELECT COUNT(*) FROM enrichments WHERE threat_level='HIGH'").fetchone()[0]
        tor_ips      = conn.execute("SELECT COUNT(*) FROM enrichments WHERE is_tor=1").fetchone()[0]

        print("\n" + "=" * 50)
        print("  T-POT PIPELINE - DATABASE SUMMARY")
        print("=" * 50)
        print(f"  Total events:        {total_events:,}")
        print(f"  Unique source IPs:   {total_ips:,}")
        print(f"  Enriched IPs:        {enriched_ips:,}")
        print(f"  CRITICAL threat IPs: {crit_ips:,}")
        print(f"  HIGH threat IPs:     {high_ips:,}")
        print(f"  Tor exit nodes:      {tor_ips:,}")
        print()

        # Top attackers
        top = self.get_top_attackers(5)
        if top:
            print("  Top 5 Attacking IPs:")
            print(f"  {'IP':<18} {'Events':<8} {'Score':<8} {'Level':<10} {'Country'}")
            print("  " + "-" * 60)
            for r in top:
                print(f"  {r['src_ip']:<18} {r['event_count']:<8} "
                      f"{r.get('abuse_score') or 0:<8} "
                      f"{r.get('threat_level') or 'UNKNOWN':<10} "
                      f"{r.get('country') or 'N/A'}")

        # Services
        services = self.get_attack_summary_by_service()
        if services:
            print()
            print("  Events by Honeypot Service:")
            for s in services:
                print(f"    {s['service']:<15} {s['events']:>6} events | {s['unique_ips']:>4} unique IPs")

        print("=" * 50 + "\n")
