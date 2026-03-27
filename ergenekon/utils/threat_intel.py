from __future__ import annotations

from functools import lru_cache

import requests
from requests.exceptions import HTTPError

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
OPENTIP_API_URL = "https://opentip.kaspersky.com/api/v1/search/hash?request={hash}"


@lru_cache(maxsize=1024)
def lookup_vt(hash_value: str, api_key: str) -> tuple[int | None, int | None, str]:
    """Query VirusTotal by file hash.

    Returns:
        A tuple of (detections, total_engines, ratio_text).
        When API limit is reached, ratio_text is ``"RATE_LIMIT"``.
    """
    try:
        resp = requests.get(
            VT_API_URL.format(hash=hash_value),
            headers={"x-apikey": api_key},
            timeout=15,
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        det = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in stats)
        return det, total, f"{det}/{total}"
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return None, None, "RATE_LIMIT"
        if e.response is not None and e.response.status_code == 404:
            return None, None, "N/A"
        return None, None, ""
    except (ValueError, KeyError):
        return None, None, ""


@lru_cache(maxsize=1024)
def lookup_opentip(hash_value: str, api_key: str) -> str:
    """Query Kaspersky OpenTIP by file hash.

    Returns:
        OpenTIP status text. When API limit is reached, returns ``"RATE_LIMIT"``.
    """
    try:
        resp = requests.get(
            OPENTIP_API_URL.format(hash=hash_value),
            headers={"x-api-key": api_key},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("FileGeneralInfo", {}).get("FileStatus")
        return status or "N/A"
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return "RATE_LIMIT"
        if e.response is not None and e.response.status_code == 404:
            return "N/A"
        return ""
    except (ValueError, KeyError):
        return ""
