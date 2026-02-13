

from typing import Optional


# Minimal demo database (replace later with real OUI DB)
VENDORS = {
    "00:1a:2b": "ExampleCorp",
    "3c:5a:b4": "Intel",
}


def lookup_vendor(mac: str) -> Optional[str]:
    if not mac:
        return None

    prefix = mac.lower()[0:8]
    return VENDORS.get(prefix)
