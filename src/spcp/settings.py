
from pathlib import Path

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

settings = Settings()
settings.spcp_data_dir.mkdir(parents=True, exist_ok=True)
