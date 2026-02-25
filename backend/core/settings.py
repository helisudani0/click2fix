import os
import yaml

CONFIG_PATH = os.getenv(
    "CONFIG_PATH",
    os.path.join(os.path.dirname(__file__), "..", "config", "settings.yaml")
)


def load_settings():
    with open(CONFIG_PATH, "r") as handle:
        return yaml.safe_load(handle) or {}


SETTINGS = load_settings()
