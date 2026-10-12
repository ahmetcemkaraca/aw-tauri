"""Desktop preparation must rebuild embedded assets from the selected WebUI."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("make"), "Make is required")
class PrebuildTests(unittest.TestCase):
    def test_existing_webui_output_is_rebuilt(self):
        makefile = Path(__file__).resolve().parents[1] / "Makefile"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ui = root / "ui"
            (ui / "dist").mkdir(parents=True)
            (ui / "static").mkdir()
            (ui / ".git").touch()
            (ui / "static/peakactivity.svg").write_text("synthetic icon")
            (root / "package-lock.json").write_text("{}")
            (root / "node_modules").mkdir()
            (root / "src-tauri/icons").mkdir(parents=True)
            (root / "src-tauri/icons/icon.png").write_bytes(b"synthetic icon")
            (ui / "dist/index.html").write_text("stale")
            (ui / "Makefile").write_text("build:\n\tprintf fresh > dist/index.html\n")
            subprocess.run(["make", "-f", str(makefile), "prebuild", "WEBUI_DIR=ui"],
                           cwd=root, capture_output=True, check=True)
            self.assertEqual((ui / "dist/index.html").read_text(), "fresh")


if __name__ == "__main__":
    unittest.main()
