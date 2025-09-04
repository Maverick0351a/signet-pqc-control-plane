
from pathlib import Path
import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    spcp_data_dir: Path = Path("./data")
    # Circuit breaker defaults
    cb_error_rate_threshold: float = 0.10  # 10%
    cb_window_size: int = 50
    cb_min_events: int = 20
    # Soft policy enforcement deny receipt rate limiting
    soft_policy_deny_limit: int = 20  # max emits per minute

    def soft_policy_window_seconds(self) -> int:  # helper accessor
        return 60

    # PCH (HTTP Message Signatures) verify-only feature flags
    pch_verify_only: bool = True  # gate overall behavior (verify but do not enforce)
    pch_max_age_seconds: int = 300  # skew window for created parameter
    pch_require_nonce: bool = False  # future enforce toggle
    pch_nonce_cache_size: int = 2048
    pch_nonce_ttl_seconds: int = 600
    # Maximum allowed future skew (seconds) for PCH `created` parameter
    pch_future_skew_seconds: int = 120
    # New PCH middleware config
    pch_required_routes: list[str] = []  # comma separated via env PCH_REQUIRED_ROUTES
    pch_max_header_bytes: int = 1536
    pch_nonce_ttl_enforcer_seconds: int = 300

    def model_post_init(self, __context):  # type: ignore[override]
        # Parse env var for required routes if present
        routes = os.getenv("PCH_REQUIRED_ROUTES")
        if routes:
            self.pch_required_routes = [r.strip() for r in routes.split(",") if r.strip()]

settings = Settings()
settings.spcp_data_dir.mkdir(parents=True, exist_ok=True)
