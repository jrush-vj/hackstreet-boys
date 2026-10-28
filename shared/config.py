from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Env vars from docs/04-system-design.md section 3. Defaults match .env.example."""

    llm_mode: Literal["mock", "kaggle", "local"] = "mock"
    defense_llm_url: str = "http://mock-llm:8009"
    defense_llm_key: str = ""
    local_llm_url: str = "http://host.docker.internal:8080"
    demo_offline: bool = False
    divert_threshold: float = 0.7
    redis_url: str = "redis://redis:6379/0"
    database_url: str = "postgresql://sphere:sphere@postgres:5432/sphere"
    gateway_url: str = "http://gateway:8000"
    bank_url: str = "http://bank:8001"
    bank_sandbox_url: str = "http://bank-sandbox:8001"
    honeypot_url: str = "http://honeypot:8002"
    sandbox_url: str = "http://sandbox:8003"
    analyst_url: str = "http://analyst:8004"
    runner_url: str = "http://runner:8005"
    runner_allowed_targets: str = "http://gateway:8000"  # comma-separated
    admin_token: str = "dev-admin-token"  # honeypot console write actions (X-Admin-Token header)


settings = Settings()
