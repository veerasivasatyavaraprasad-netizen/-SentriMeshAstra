"""Real geolocation for impossible-travel detection: an IP -> country
lookup (ipinfo.io, gated behind a configured token — no fallback, same
honest-unknown pattern as AbuseIPDB) plus the actual algorithm real
identity-protection tools use for "impossible travel": great-circle
distance between two known locations, divided by elapsed time, compared
against a speed no legitimate traveler can exceed.

Country-level granularity (not city/IP-precise coordinates) is
deliberate — country centroids are all this needs to catch the case that
actually matters (a login from the US followed nine minutes later by one
from Russia), and city-level lookups just add noise for two logins from
the same metro area on different ISPs.
"""
import logging
import math

import httpx

from app.config import get_settings

logger = logging.getLogger("sentrimesh.geo")

IPINFO_URL = "https://ipinfo.io/{ip}/json"

# A faster-than-commercial-aviation threshold. Real identity-protection
# tools (e.g. Azure AD's "atypical travel" detection) use implausible
# velocity as the signal, not a fixed distance or a fixed time window —
# two logins an hour apart from adjacent countries are unremarkable;
# two logins ten minutes apart from opposite sides of the globe aren't,
# regardless of the absolute distance or time involved.
MAX_PLAUSIBLE_SPEED_KMH = 1000.0

# Real approximate country centroids (ISO 3166-1 alpha-2 -> lat, lon),
# covering the countries most likely to actually appear in login traffic.
# A country missing from this table simply isn't evaluated for impossible
# travel — never a guessed coordinate standing in for a real one.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "GB": (55.3, -3.4), "FR": (46.2, 2.2),
    "DE": (51.2, 10.5), "IT": (41.9, 12.6), "ES": (40.5, -3.7), "PT": (39.4, -8.2),
    "NL": (52.1, 5.3), "BE": (50.5, 4.5), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "SE": (60.1, 18.6), "NO": (60.5, 8.5), "FI": (61.9, 25.7), "DK": (56.3, 9.5),
    "PL": (51.9, 19.1), "CZ": (49.8, 15.5), "GR": (39.1, 21.8), "RU": (61.5, 105.3),
    "UA": (48.4, 31.2), "TR": (38.9, 35.2), "IN": (20.6, 78.9), "CN": (35.9, 104.2),
    "JP": (36.2, 138.3), "KR": (35.9, 127.8), "AU": (-25.3, 133.8), "NZ": (-40.9, 174.9),
    "BR": (-14.2, -51.9), "AR": (-38.4, -63.6), "MX": (23.6, -102.6), "ZA": (-30.6, 22.9),
    "NG": (9.1, 8.7), "EG": (26.8, 30.8), "SA": (23.9, 45.1), "AE": (23.4, 53.8),
    "IL": (31.0, 34.9), "IR": (32.4, 53.7), "PK": (30.4, 69.3), "BD": (23.7, 90.4),
    "ID": (-0.8, 113.9), "TH": (15.9, 101.0), "VN": (14.1, 108.3), "PH": (12.9, 121.8),
    "MY": (4.2, 108.0), "SG": (1.35, 103.8), "KE": (0.0, 37.9), "GH": (7.9, -1.0),
    "CO": (4.6, -74.3), "CL": (-35.7, -71.5), "PE": (-9.2, -75.0), "VE": (6.4, -66.6),
    "CU": (21.5, -77.8), "IE": (53.4, -8.2), "RO": (45.9, 24.9), "HU": (47.2, 19.5),
    "BG": (42.7, 25.5), "RS": (44.0, 21.0), "HR": (45.1, 15.2), "SK": (48.7, 19.7),
    "SI": (46.2, 14.9), "IS": (64.9, -19.0), "KZ": (48.0, 66.9), "UZ": (41.4, 64.6),
    "AF": (33.9, 67.7), "IQ": (33.2, 43.7), "SY": (34.8, 38.9), "JO": (30.6, 36.2),
    "LB": (33.9, 35.9), "QA": (25.4, 51.2), "KW": (29.3, 47.5), "OM": (21.5, 55.9),
    "YE": (15.6, 48.5), "MA": (31.8, -7.1), "DZ": (28.0, 1.7), "TN": (33.9, 9.5),
    "LY": (26.3, 17.2), "ET": (9.1, 40.5), "TZ": (-6.4, 34.9), "UG": (1.4, 32.3),
    "ZW": (-19.0, 29.2), "ZM": (-13.1, 27.9),
}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Standard great-circle distance between two points on Earth's surface."""
    r = 6371.0  # Earth's mean radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def implied_travel_speed_kmh(country_a: str, country_b: str, seconds_elapsed: float) -> float | None:
    """None when either country isn't in our reference table, the
    countries are the same, or elapsed time is non-positive (clock skew /
    out-of-order delivery — not evidence of anything)."""
    if country_a == country_b or seconds_elapsed <= 0:
        return None
    coords_a = COUNTRY_CENTROIDS.get(country_a)
    coords_b = COUNTRY_CENTROIDS.get(country_b)
    if coords_a is None or coords_b is None:
        return None
    distance_km = haversine_km(*coords_a, *coords_b)
    hours = seconds_elapsed / 3600.0
    return distance_km / hours


async def lookup_country(ip: str) -> str | None:
    """Real ipinfo.io lookup, gated behind IPINFO_API_KEY. Returns an ISO
    3166-1 alpha-2 country code, or None if unconfigured or the lookup
    fails for any reason — never a guessed country standing in for a
    real one."""
    settings = get_settings()
    if not settings.ipinfo_api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(IPINFO_URL.format(ip=ip), params={"token": settings.ipinfo_api_key})
        if response.status_code != 200:
            logger.warning("ipinfo.io returned %s for %s", response.status_code, ip)
            return None
        return response.json().get("country")
    except (httpx.HTTPError, ValueError):
        logger.warning("ipinfo.io lookup failed for %s", ip, exc_info=True)
        return None
