from __future__ import annotations

from greynoc_detector_engine.config.settings import Settings, get_settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage


def get_storage() -> SQLiteStorage:
    settings = get_settings()
    storage = SQLiteStorage(settings.database_path)
    storage.initialize()
    return storage


def get_app_settings() -> Settings:
    return get_settings()
