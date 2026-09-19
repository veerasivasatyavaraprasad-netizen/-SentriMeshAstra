from app.geo import haversine_km, implied_travel_speed_kmh, MAX_PLAUSIBLE_SPEED_KMH


def test_haversine_zero_distance_for_same_point():
    assert haversine_km(40.0, -74.0, 40.0, -74.0) == 0


def test_haversine_known_distance_new_york_to_london():
    # Real-world great-circle distance NYC <-> London is ~5570 km.
    distance = haversine_km(40.7128, -74.0060, 51.5074, -0.1278)
    assert 5400 < distance < 5700


def test_implied_travel_speed_same_country_is_none():
    assert implied_travel_speed_kmh("US", "US", 60) is None


def test_implied_travel_speed_zero_or_negative_elapsed_is_none():
    assert implied_travel_speed_kmh("US", "RU", 0) is None
    assert implied_travel_speed_kmh("US", "RU", -10) is None


def test_implied_travel_speed_unknown_country_is_none():
    assert implied_travel_speed_kmh("US", "ZZ", 3600) is None  # ZZ isn't a real country in our table


def test_implied_travel_speed_us_to_russia_in_ten_minutes_is_impossible():
    speed = implied_travel_speed_kmh("US", "RU", 600)  # 10 minutes
    assert speed is not None
    assert speed > MAX_PLAUSIBLE_SPEED_KMH


def test_implied_travel_speed_us_to_canada_over_a_day_is_plausible():
    """Adjacent countries over a realistic timeframe should never trip
    the impossible-travel threshold — this is the false-positive check."""
    speed = implied_travel_speed_kmh("US", "CA", 24 * 3600)
    assert speed is not None
    assert speed < MAX_PLAUSIBLE_SPEED_KMH
