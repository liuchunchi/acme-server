from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    base_url: str = "http://localhost:8000"

    ca_key_path: Path = Path("ca/ca_key.pem")
    ca_cert_path: Path = Path("ca/ca_cert.pem")

    ca_key_size: int = 4096
    ca_common_name: str = "ACME Test CA"
    ca_country: str = "CN"
    ca_organization: str = "ACME Test"

    cert_validity_days: int = 90
    order_validity_hours: int = 24
    authz_validity_hours: int = 24

    auto_accept_challenges: bool = False
    dns_resolvers: list[str] = ["8.8.8.8", "8.8.4.4"]
    
    hint_config: dict[str, list[str]] = {
        "hsm": ["hwmodel", "swversion", "submods", "manifests", "hsmmeta"],
        "measured_boot": ["measured", "bootmeta"],
        "os_patch_level":["patch", "levelmeta"],
        "sw_manifest":["manifests", "swversion", "swmeta"],
        "fido2":["fido2meta"]
        
    }

    @property
    def directory_url(self) -> str:
        return f"{self.base_url}/directory"

    model_config = {"env_prefix": "ACME_", "env_file": ".env"}


settings = Settings()
