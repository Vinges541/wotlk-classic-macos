"""Default directories, retaining existing installation paths and saved login."""
import os
from pathlib import Path

STATE_NAME = 'WoTLK Classic Bridge'
# Compatibility only: state contains absolute paths and must not be moved blindly.
LEGACY_STATE_NAME = 'Wrath Classic Bridge'


def default_state(windows=False):
    if os.environ.get('WRATH_STATE'):
        return Path(os.environ['WRATH_STATE'])
    base = (Path(os.environ.get('LOCALAPPDATA', Path.home())) if windows
            else Path.home() / 'Library/Application Support')
    current, legacy = base / STATE_NAME, base / LEGACY_STATE_NAME
    if not current.exists() and legacy.exists():
        return legacy
    return current
