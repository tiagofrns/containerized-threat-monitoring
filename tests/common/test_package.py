"""Submission files must include runtime units and exclude temporary/private data."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('package_project', ROOT/'scripts/common/package-project.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def test_timer_socket_and_message_index_are_included(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in package.DIRECTORIES:
                (root/name).mkdir()
            names = ['README.md', '.gitignore', 'monitoring/health.timer',
                     'monitoring/demo.socket', 'evidence/messages.tsv']
            for name in names:
                (root/name).write_text('fixture')
            (root/'monitoring/webhook-secret').write_text('private fixture')
            (root/'scripts/results').mkdir()
            (root/'scripts/results/temporary.json').write_text('{}')
            with patch.object(package, 'ROOT', root):
                selected = {path.relative_to(root).as_posix() for path in package.source_files()}
            self.assertEqual(selected, set(names))

    def test_archive_uses_the_project_directory_name(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            package.write_member(archive, 'README.md', b'fixture', 0o644)
        buffer.seek(0)
        with tarfile.open(fileobj=buffer, mode='r') as archive:
            self.assertEqual(archive.getnames(), ['security-monitoring-platform/README.md'])


if __name__ == '__main__':
    unittest.main()
