from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "APEX Dynamic Service"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./apex.db"
    
    # CORS Configuration
    # Defaults to common local dev ports. Override with ["*"] in env for permissive mode.
    ALLOWED_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Phase 2: Rate Limiting & Logging
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "60/minute"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    class Config:
        env_file = ".env"

settings = Settings()

# Direct export for easy imports
VERSION = settings.VERSION
DATABASE_URL = settings.DATABASE_URL
ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS
RATE_LIMIT_ENABLED = settings.RATE_LIMIT_ENABLED
RATE_LIMIT_DEFAULT = settings.RATE_LIMIT_DEFAULT
LOG_LEVEL = settings.LOG_LEVEL
LOG_FORMAT = settings.LOG_FORMAT
