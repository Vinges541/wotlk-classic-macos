"""Windows line endings must not change source pin identity or applied content."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_tools

PATCH = b'''diff --git a/example.txt b/example.txt
--- a/example.txt
+++ b/example.txt
@@ -1 +1 @@
-before
+after
'''


class SourcePinTests(unittest.TestCase):
    def fixture(self, root, endings, stamp_hash=None, commit='abc123'):
        repo = root / 'launcher'
        (repo / 'patches').mkdir(parents=True)
        (repo / 'patches/cascette-macos.patch').write_bytes(PATCH.replace(b'\n', endings))
        state = root / 'state'
        source = state / 'src/cascette-py'
        source.mkdir(parents=True)
        if stamp_hash:
            (source / '.wrath-source.json').write_text(json.dumps({'commit': commit, 'patch_sha256': stamp_hash}))
        return repo, state, source

    def test_lf_stamp_accepts_crlf_checkout_without_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, state, source = self.fixture(Path(tmp), b'\r\n', hashlib.sha256(PATCH).hexdigest())
            with patch.object(build_tools, 'REPO', repo), \
                 patch.dict(build_tools.PINS['sources'], {'cascette-py': {'commit': 'abc123'}}), \
                 patch.object(build_tools, 'run') as run:
                self.assertEqual(build_tools.source('cascette-py', state), source)
                run.assert_not_called()

    def test_crlf_stamp_migrates_without_touching_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, state, source = self.fixture(Path(tmp), b'\n', hashlib.sha256(PATCH.replace(b'\n', b'\r\n')).hexdigest())
            (source / 'keep.txt').write_text('existing source')
            with patch.object(build_tools, 'REPO', repo), \
                 patch.dict(build_tools.PINS['sources'], {'cascette-py': {'commit': 'abc123'}}), \
                 patch.object(build_tools, 'run') as run:
                build_tools.source('cascette-py', state)
                run.assert_not_called()
            self.assertEqual(json.loads((source / '.wrath-source.json').read_text())['patch_sha256'], hashlib.sha256(PATCH).hexdigest())
            self.assertEqual((source / 'keep.txt').read_text(), 'existing source')

    def test_real_pin_changes_are_rejected_without_mutation(self):
        for commit, digest in [('other', hashlib.sha256(PATCH).hexdigest()),
                               ('abc123', 'f' * 64),
                               ('other', hashlib.sha256(PATCH.replace(b'\n', b'\r\n')).hexdigest())]:
            with self.subTest(commit=commit, digest=digest), tempfile.TemporaryDirectory() as tmp:
                repo, state, source = self.fixture(Path(tmp), b'\r\n', digest, commit)
                stamp = source / '.wrath-source.json'
                before = stamp.read_bytes()
                with patch.object(build_tools, 'REPO', repo), \
                     patch.dict(build_tools.PINS['sources'], {'cascette-py': {'commit': 'abc123'}}), \
                     patch.object(build_tools, 'run') as run:
                    with self.assertRaisesRegex(RuntimeError, 'Source pin changed for cascette-py'):
                        build_tools.source('cascette-py', state)
                    run.assert_not_called()
                self.assertEqual(stamp.read_bytes(), before)

    def test_crlf_patch_is_applied_as_lf_to_real_git_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, state, source = self.fixture(Path(tmp), b'\r\n')
            subprocess.run(['git', 'init', str(source)], check=True, capture_output=True)
            (source / '.git/wrath-owned').touch()
            (source / 'example.txt').write_bytes(b'before\n')
            subprocess.run(['git', '-C', str(source), 'add', 'example.txt'], check=True, capture_output=True)
            paths = []
            def run(argv):
                if 'apply' in argv:
                    paths.append(argv[-1])
                    self.assertEqual(argv[-1].read_bytes(), PATCH)
                    subprocess.run([str(a) for a in argv], check=True, capture_output=True)
                # Network/fetch/checkout are unrelated to this local patch test.
            with patch.object(build_tools, 'REPO', repo), \
                 patch.dict(build_tools.PINS['sources'], {'cascette-py': {'commit': 'abc123'}}), \
                 patch.object(build_tools, 'run', side_effect=run):
                build_tools.source('cascette-py', state)
            self.assertEqual((source / 'example.txt').read_bytes(), b'after\n')
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(not path.exists() for path in paths))
            self.assertEqual(json.loads((source / '.wrath-source.json').read_text())['patch_sha256'], hashlib.sha256(PATCH).hexdigest())
