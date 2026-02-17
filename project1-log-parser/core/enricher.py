"""
core/enricher.py

IP Enrichment via multiple free/freemium Threat Intelligence APIs:

  1. ip-api.com       - Geolocation, ISP, ASN (free, no key needed)
  2. AbuseIPDB        - Abuse confidence score, report count (free tier: 1000/day)
  3. VirusTotal       - AV detections, malware associations (free tier: 4/min, 500/day)
  4. Shodan           - Open ports, banners, CVEs (free tier: requires key, 1/sec)

All results are cached in the SQLite DB. IPs are only re-queried after the
configured cache TTL (default: 7 days) to preserve API rate limits.

Rate limiting is handled per-API using a token bucket approach with
configurable delays between requests.
"""

import time
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Tuple, Optional

logger = logging.getLogger("tpot_pipeline.enricher")


class IPEnricher:
    """
    Fetches threat intelligence for each unique IP in the database,
    enriching records with geo, abuse score, and open port data.
    """

    def __init__(self, db, config: dict):
        self.db = db
        self.config = config
        self.api_keys = config.get("api_keys", {})
        self.cache_ttl_days = config.get("cache_ttl_days", 7)

        # Per-API delay in seconds to respect rate limits
        self.rate_limits = {
            "ip_api":     0.5,   # ip-api: 45 req/min on free (generous)
            "abuseipdb":  1.1,   # AbuseIPDB: free = 1000/day
            "virustotal": 15.5,  # VirusTotal free: 4/min = 1 per 15s
            "shodan":     1.1,   # Shodan free: 1/sec
        }

    def run(self) -> Tuple[int, int]:
        """
        Main entry. Enriches all IPs not yet enriched (or with stale cache).
        Returns (enriched_count, skipped_count).
        """
        try:
            import requests
        except ImportError:
            logger.error("requests library not found. Install: pip install requests")
            return 0, 0

        pending_ips = self.db.get_unenriched_ips(self.cache_ttl_days)
        total = len(pending_ips)
        logger.info("  IPs pending enrichment: %d", total)

        enriched = 0
        for i, ip in enumerate(pending_ips, 1):
            logger.info("  [%d/%d] Enriching: %s", i, total, ip)
            data = self._enrich_ip(ip, requests)
            if data:
                self.db.upsert_enrichment(ip, data)
                enriched += 1

        skipped = self.db.count_cached_ips(self.cache_ttl_days)
        return enriched, skipped

    def _enrich_ip(self, ip: str, requests) -> Optional[dict]:
        """Collect enrichment from all configured APIs for a single IP."""
        result = {"ip": ip, "enriched_at": datetime.utcnow().isoformat()}

        # 1. Geolocation (always run - no key needed)
        geo = self._query_ip_api(ip, requests)
        result.update(geo)
        time.sleep(self.rate_limits["ip_api"])

        # 2. AbuseIPDB
        if self.api_keys.get("abuseipdb"):
            abuse = self._query_abuseipdb(ip, requests)
            result.update(abuse)
            time.sleep(self.rate_limits["abuseipdb"])
        else:
            logger.debug("    AbuseIPDB: no API key configured, skipping")

        # 3. VirusTotal
        if self.api_keys.get("virustotal"):
            vt = self._query_virustotal(ip, requests)
            result.update(vt)
            time.sleep(self.rate_limits["virustotal"])
        else:
            logger.debug("    VirusTotal: no API key configured, skipping")

        # 4. Shodan
        if self.api_keys.get("shodan"):
            shodan = self._query_shodan(ip, requests)
            result.update(shodan)
            time.sleep(self.rate_limits["shodan"])
        else:
            logger.debug("    Shodan: no API key configured, skipping")

        return result

    # ------------------------------------------------------------------
    # API Queries
    # ------------------------------------------------------------------

    def _query_ip_api(self, ip: str, requests) -> dict:
        """
        ip-api.com - Free geolocation, no key required.
        Returns: country, city, ISP, ASN, timezone, lat/lon
        Rate limit: 45 req/min on free tier (no key)
        """
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            d = resp.json()
            if d.get("status") == "success":
                logger.debug("    ip-api: %s -> %s, %s (%s)", ip, d.get("city"), d.get("country"), d.get("isp"))
                return {
                    "country":      d.get("country"),
                    "country_code": d.get("countryCode"),
                    "region":       d.get("regionName"),
                    "city":         d.get("city"),
                    "latitude":     d.get("lat"),
                    "longitude":    d.get("lon"),
                    "timezone":     d.get("timezone"),
                    "isp":          d.get("isp"),
                    "org":          d.get("org"),
                    "asn":          d.get("as"),
                    "asn_name":     d.get("asname"),
                }
            else:
                logger.warning("    ip-api error for %s: %s", ip, d.get("message"))
        except Exception as e:
            logger.error("    ip-api failed for %s: %s", ip, e)
        return {}

    def _query_abuseipdb(self, ip: str, requests) -> dict:
        """
        AbuseIPDB - Abuse confidence score and report history.
        Free tier: 1,000 checks/day | Key: https://www.abuseipdb.com/account/api

        Returns: abuse_score (0-100), total_reports, last_reported_at,
                 usage_type, domain, is_tor, is_public
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key":    self.api_keys["abuseipdb"],
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            d = resp.json().get("data", {})
            logger.debug("    AbuseIPDB: %s -> score=%s, reports=%s",
                         ip, d.get("abuseConfidenceScore"), d.get("totalReports"))
            return {
                "abuse_score":      d.get("abuseConfidenceScore", 0),
                "abuse_reports":    d.get("totalReports", 0),
                "abuse_last_seen":  d.get("lastReportedAt"),
                "usage_type":       d.get("usageType"),
                "domain":           d.get("domain"),
                "is_tor":           d.get("isTor", False),
                "is_public":        d.get("isPublic", True),
                "country_code":     d.get("countryCode"),  # fill in if ip-api missed
            }
        except Exception as e:
            logger.error("    AbuseIPDB failed for %s: %s", ip, e)
        return {}

    def _query_virustotal(self, ip: str, requests) -> dict:
        """
        VirusTotal - AV vendor detections for the IP.
        Free tier: 4 req/min, 500 req/day | Key: https://www.virustotal.com/gui/my-apikey

        Returns: vt_malicious (count of vendors flagging as malicious),
                 vt_suspicious, vt_harmless, vt_undetected, vt_last_analysis
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_keys["virustotal"]}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 404:
                logger.debug("    VirusTotal: %s not found", ip)
                return {}
            resp.raise_for_status()
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.debug("    VirusTotal: %s -> malicious=%s", ip, stats.get("malicious"))
            return {
                "vt_malicious":    stats.get("malicious", 0),
                "vt_suspicious":   stats.get("suspicious", 0),
                "vt_harmless":     stats.get("harmless", 0),
                "vt_undetected":   stats.get("undetected", 0),
                "vt_last_analysis": resp.json().get("data", {}).get("attributes", {}).get("last_analysis_date"),
            }
        except Exception as e:
            logger.error("    VirusTotal failed for %s: %s", ip, e)
        return {}

    def _query_shodan(self, ip: str, requests) -> dict:
        """
        Shodan - Open ports, banners, CVEs, and tags.
        Free tier: 1 req/sec | Key: https://account.shodan.io/

        Returns: open_ports (list), shodan_tags (list), vuln_count,
                 hostnames, last_update
        """
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": self.api_keys["shodan"]}

        try:
            resp = requests.get(url, params=params, timeout=15)
            if resp.status_code == 404:
                logger.debug("    Shodan: %s has no data", ip)
                return {}
            resp.raise_for_status()
            d = resp.json()
            ports     = d.get("ports", [])
            vulns     = list(d.get("vulns", {}).keys())
            tags      = d.get("tags", [])
            hostnames = d.get("hostnames", [])
            logger.debug("    Shodan: %s -> ports=%s, vulns=%s", ip, ports, len(vulns))
            return {
                "open_ports":     ",".join(str(p) for p in ports),
                "shodan_tags":    ",".join(tags),
                "vuln_cves":      ",".join(vulns),
                "vuln_count":     len(vulns),
                "hostnames":      ",".join(hostnames),
                "shodan_updated": d.get("last_update"),
            }
        except Exception as e:
            logger.error("    Shodan failed for %s: %s", ip, e)
        return {}

    # ------------------------------------------------------------------
    # Threat Classification (no API needed)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_threat_level(enrichment: dict) -> str:
        """
        Classify an IP's threat level based on enrichment data.
        Returns: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
        """
        score   = enrichment.get("abuse_score", 0) or 0
        reports = enrichment.get("abuse_reports", 0) or 0
        vt_mal  = enrichment.get("vt_malicious", 0) or 0
        is_tor  = enrichment.get("is_tor", False)
        vulns   = enrichment.get("vuln_count", 0) or 0

        if score >= 90 or vt_mal >= 10 or (is_tor and score >= 50):
            return "CRITICAL"
        if score >= 50 or vt_mal >= 5 or reports >= 100:
            return "HIGH"
        if score >= 20 or vt_mal >= 1 or reports >= 10 or vulns >= 5:
            return "MEDIUM"
        if score >= 5 or reports >= 1:
            return "LOW"
        return "UNKNOWN"
