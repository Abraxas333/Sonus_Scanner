"""
WAF signature management module.
Provides global access to preprocessed WAF signatures.
"""

import os
import re
import yaml
import logging
from scapy.all import TCP, IP

# Setup logging
logger = logging.getLogger(__name__)

# Global signature cache
_signatures = None
_last_modified_time = 0
_signature_file = os.path.join(os.path.dirname(__file__), 'waf_signatures.yml')


def preprocess_signatures(signatures):
    """Preprocess signatures for efficient matching"""
    processed = []

    for sig in signatures:
        sig_type = sig.get('type', '')

        try:
            # Content-based signatures
            if sig_type == 'content':
                sig['text'] = sig['text'].encode('utf-8')

            # Regex-based signatures
            elif sig_type == 'content_regex':
                sig['compiled_pattern'] = re.compile(sig['pattern'].encode('utf-8'))

            elif sig_type == 'header_regex':
                sig['compiled_pattern'] = re.compile(sig['pattern'], re.IGNORECASE)

            # Layer-specific signatures
            elif sig_type == 'layer_field':
                # Convert string layer names to Scapy objects
                if sig['layer'] == 'TCP':
                    sig['layer'] = TCP
                elif sig['layer'] == 'IP':
                    sig['layer'] = IP
                # Convert hex string values to integers if needed
                if isinstance(sig['value'], str) and sig['value'].startswith('0x'):
                    sig['value'] = int(sig['value'], 16)

            processed.append(sig)

        except KeyError as e:
            logger.warning(f"Signature missing required field {e}: {sig}")
        except Exception as e:
            logger.error(f"Error preprocessing signature {sig}: {e}")

    return processed


def get_signatures(force_reload=False):
    """
    Get preprocessed WAF signatures.

    Args:
        force_reload (bool): Force reload from YAML even if cached

    Returns:
        list: Preprocessed WAF signatures
    """
    global _signatures, _last_modified_time, _signature_file

    # Check if signatures need to be loaded or reloaded
    current_mtime = os.path.getmtime(_signature_file) if os.path.exists(_signature_file) else 0

    if _signatures is None or current_mtime > _last_modified_time or force_reload:
        logger.info(f"Loading WAF signatures from {_signature_file}")

        try:
            with open(_signature_file, 'r') as f:
                yaml_data = yaml.safe_load(f)
                raw_signatures = yaml_data.get('waf_signatures', [])

            # Preprocess signatures
            _signatures = preprocess_signatures(raw_signatures)
            _last_modified_time = current_mtime

            logger.info(f"Loaded {len(_signatures)} WAF signatures")

        except Exception as e:
            logger.error(f"Error loading WAF signatures: {e}")
            if _signatures is None:  # First load failed
                _signatures = []  # Initialize with empty list to avoid repeated errors

    return _signatures


def reload_signatures():
    """Force reload of signatures from YAML file"""
    return get_signatures(force_reload=True)


# Initialize signatures at module import time
get_signatures()