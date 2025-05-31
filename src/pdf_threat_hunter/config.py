from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()           # single place where .env is loaded

class Settings(BaseSettings):
    openai_api_key: str | None = None
    vt_api_key: str | None = None
    urlscan_api_key: str | None = None


settings = Settings()