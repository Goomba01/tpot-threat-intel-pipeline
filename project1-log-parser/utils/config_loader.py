"""
utils/config_loader.py

Loads and validates the pipeline configuration from a YAML file.
Falls back to defaults if the file is missing or a key is absent.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger("tpot_pipeline.config")


DEFAULTS = {
    "cache_ttl_days": 7,
    "api_keys": {
        "abuseipdb":  None,
        "virustotal": None,
        "shodan":     None,
    },
    "rate_limits": {
        "ip_api":     0.5,
        "abuseipdb":  1.1,
        "virustotal": 15.5,
        "shodan":     1.1,
    },
    "log_paths": {
        "cowrie":    "/data/cowrie/log/",
        "dionaea":   "/data/dionaea/log/",
        "suricata":  "/data/suricata/log/",
        "honeytrap": "/data/honeytrap/log/",
    }
}


def load_config(config_path: str) -> dict:
    """
    Load config from YAML file. Returns merged config with defaults.
    Also reads API keys from environment variables as a fallback
    (e.g., ABUSEIPDB_KEY, VIRUSTOTAL_KEY, SHODAN_KEY).
    """
    config = dict(DEFAULTS)
    config["api_keys"] = dict(DEFAULTS["api_keys"])

    # Try to load YAML config
    path = Path(config_path)
    if path.exists():
        try:
            import yaml
            with open(path) as f:
                loaded = yaml.safe_load(f) or {}
            # Deep merge api_keys
            if "api_keys" in loaded:
                config["api_keys"].update(loaded.pop("api_keys"))
            config.update(loaded)
            logger.info("Config loaded from: %s", config_path)
        except ImportError:
            logger.warning("PyYAML not installed (pip install pyyaml). Using defaults + env vars.")
        except Exception as e:
            logger.warning("Could not load config %s: %s — using defaults", config_path, e)
    else:
        logger.info("No config file found at %s — using defaults + env vars", config_path)

    # Environment variable overrides (safer than putting keys in a file)
    env_map = {
        "ABUSEIPDB_KEY":  "abuseipdb",
        "VIRUSTOTAL_KEY": "virustotal",
        "SHODAN_KEY":     "shodan",
    }
    for env_var, key_name in env_map.items():
        val = os.environ.get(env_var)
        if val:
            config["api_keys"][key_name] = val
            logger.debug("API key loaded from env: %s", env_var)

    # Report which APIs are configured
    configured = [k for k, v in config["api_keys"].items() if v]
    unconfigured = [k for k, v in config["api_keys"].items() if not v]

    logger.info("APIs configured: %s", configured if configured else ["none"])
    if unconfigured:
        logger.info("APIs not configured (add keys to config.yaml or env vars): %s", unconfigured)

    return config
