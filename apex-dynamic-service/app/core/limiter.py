from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core import config

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[config.RATE_LIMIT_DEFAULT],
    enabled=config.RATE_LIMIT_ENABLED,
    storage_uri="memory://" # Default to memory for now
)
