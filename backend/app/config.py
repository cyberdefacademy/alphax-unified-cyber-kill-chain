from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://alphax:alphax_secret@localhost:5432/alphax"
    jwt_secret: str = "change_me_in_prod_alphax_2026_32chars_min"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    executor_mode: str = "host"  # host | docker
    allowed_tools: str = "nmap,msfvenom,msfconsole,hydra,hashcat,sqlmap,nikto,smbclient,psexec.py,wmiexec.py,secretsdump.py,crackmapexec,linpeas,winpeas,chisel,ligolo,scp,nuclei,dirb,gobuster"
    vulnhub_targets: str = "192.168.56.0/24,10.0.0.0/24"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    alphax_operator_user: str = "operator"
    alphax_operator_password: str = "AlphaX!2026"

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def allowed_tools_set(self) -> set[str]:
        return {t.strip() for t in self.allowed_tools.split(",") if t.strip()}

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
