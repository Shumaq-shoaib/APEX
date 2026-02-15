from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "APEX Dynamic Service"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./apex.db"
    
    class Config:
        env_file = ".env"

settings = Settings()

# Direct export for easy imports
VERSION = settings.VERSION
DATABASE_URL = settings.DATABASE_URL
