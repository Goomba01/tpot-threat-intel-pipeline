#!/usr/bin/env python3
"""
T-Pot Threat Intelligence Pipeline - Project 1
Log Parser & IP Enricher

Usage:
    python main.py --log-dir /data/elk/logstash/
    python main.py --log-dir ./sample_logs/ --dry-run
    python main.py --enrich-only       # Re-enrich IPs already in DB
    python main.py --stats             # Print DB summary stats
"""

import argparse
import logging
import sys
from pathlib import Path

from core.parser import TpotLogParser
from core.enricher import IPEnricher
from core.database import ThreatDatabase
from utils.logger import setup_logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="T-Pot Log Parser & IP Enricher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--log-dir", default="/data/elk/logstash/",
                        help="Path to T-Pot log directory (default: /data/elk/logstash/)")
    parser.add_argument("--db-path", default="./tpot_threats.db",
                        help="SQLite DB output path (default: ./tpot_threats.db)")
    parser.add_argument("--config", default="./config/config.yaml",
                        help="Config file path (default: ./config/config.yaml)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse logs but skip API enrichment")
    parser.add_argument("--enrich-only", action="store_true",
                        help="Skip parsing, re-enrich existing IPs in DB")
    parser.add_argument("--stats", action="store_true",
                        help="Print database summary and exit")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")
    return parser.parse_args()


def main():
    args = parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger("tpot_pipeline", log_level)

    logger.info("=" * 60)
    logger.info("T-Pot Threat Intelligence Pipeline - Project 1")
    logger.info("=" * 60)

    # Initialise DB
    db = ThreatDatabase(args.db_path)
    db.initialise()

    if args.stats:
        db.print_stats()
        return

    # Load config
    from utils.config_loader import load_config
    config = load_config(args.config)

    if not args.enrich_only:
        # --- PHASE 1: Parse T-Pot logs ---
        logger.info("[Phase 1] Parsing T-Pot logs from: %s", args.log_dir)
        parser = TpotLogParser(args.log_dir, db)
        events, unique_ips = parser.run()
        logger.info("  Parsed %d events | %d unique source IPs", events, unique_ips)
    else:
        logger.info("[Phase 1] Skipped (--enrich-only)")

    if args.dry_run:
        logger.info("[Phase 2] Skipped (--dry-run)")
    else:
        # --- PHASE 2: Enrich IPs via threat intel APIs ---
        logger.info("[Phase 2] Enriching IPs via threat intel APIs...")
        enricher = IPEnricher(db, config)
        enriched, skipped = enricher.run()
        logger.info("  Enriched: %d IPs | Skipped (cached): %d", enriched, skipped)

    # --- Summary ---
    logger.info("[Done] Results saved to: %s", args.db_path)
    db.print_stats()


if __name__ == "__main__":
    main()
