"""State branding must not strand existing installations or saved settings."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from paths import default_state, LEGACY_STATE_NAME, STATE_NAME
from bootstrap import state_arg


class StatePathsTests(unittest.TestCase):
    def test_new_install_uses_wotlk_name_on_both_platforms(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LOCALAPPDATA': tmp}, clear=True), patch('pathlib.Path.home', return_value=Path(tmp)):
            self.assertEqual(default_state(True), Path(tmp) / STATE_NAME)
            self.assertEqual(default_state(), Path(tmp) / 'Library/Application Support' / STATE_NAME)

    def test_existing_state_is_reused_without_moving_files(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LOCALAPPDATA': tmp}, clear=True), patch('pathlib.Path.home', return_value=Path(tmp)):
            for windows, base in [(True, Path(tmp)), (False, Path(tmp) / 'Library/Application Support')]:
                legacy = base / LEGACY_STATE_NAME
                legacy.mkdir(parents=True)
                (legacy / 'installation.json').write_text('{"target":"existing"}')
                self.assertEqual(default_state(windows), legacy)
                self.assertTrue((legacy / 'installation.json').is_file())
                current = base / STATE_NAME
                current.mkdir()
                self.assertEqual(default_state(windows), current)

    def test_explicit_overrides_win(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'WRATH_STATE': tmp}, clear=True):
            self.assertEqual(default_state(True), Path(tmp))
            self.assertEqual(default_state(), Path(tmp))
            self.assertEqual(state_arg(['run', '--state', tmp + '/custom']), Path(tmp) / 'custom')
