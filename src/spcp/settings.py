
from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    spcp_data_dir: Path = Path("./data")
    # Circuit breaker defaults
    cb_error_rate_threshold: float = 0.10  # 10%
    cb_window_size: int = 50
    cb_min_events: int = 20

settings = Settings()
settings.spcp_data_dir.mkdir(parents=True, exist_ok=True)
