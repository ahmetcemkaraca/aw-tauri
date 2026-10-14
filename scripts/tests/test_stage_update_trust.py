import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("stage_update_trust", Path(__file__).parents[1] / "stage_update_trust.py")
stage_update_trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_update_trust)


class StageUpdateTrustTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="peakactivity-update-stage-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.resources = self.root / "input"
        self.resources.mkdir()
        for name, data in (("gpgv", b"synthetic verifier"), ("trusted.gpg", b"synthetic public keyring"), ("dependency.so", b"synthetic reviewed dependency")):
            (self.resources / name).write_bytes(data)
        self.trust = {
            "schema_version": 1, "manifest_signer_fingerprint": "A" * 40,
            "source_repository": "https://source.invalid/project", "channel": "stable",
            "verifier_file": "gpgv", "keyring_file": "trusted.gpg",
            "files": [{"name": name, "sha256": hashlib.sha256((self.resources / name).read_bytes()).hexdigest()}
                      for name in ("gpgv", "trusted.gpg", "dependency.so")],
        }
        self.record = self.root / "approved-trust.json"
        self.record.write_text(json.dumps(self.trust), encoding="utf-8")
        self.output = self.root / "staged"

    def stage(self):
        return stage_update_trust.stage(self.record, self.resources, self.output)

    def assert_preserved_failure(self):
        fresh = self.root / "fresh-output"
        with self.assertRaises(ValueError):
            stage_update_trust.stage(self.record, self.resources, fresh)
        self.assertFalse(fresh.exists())
        self.output.mkdir(exist_ok=True)
        (self.output / "existing").write_bytes(b"previous approved output")
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual((self.output / "existing").read_bytes(), b"previous approved output")
        self.assertEqual(list(self.output.iterdir()), [self.output / "existing"])

    def test_copies_complete_pinned_closure_and_preserves_inputs(self):
        original = {path.name: path.read_bytes() for path in self.resources.iterdir()}
        try:
            result = self.stage()
        except ValueError as error:
            self.fail(f"complete pinned resources were rejected: {error}")
        self.assertEqual(result, self.output / "release-trust.json")
        self.assertEqual(result.read_bytes(), self.record.read_bytes())
        for name, data in original.items():
            self.assertEqual((self.output / "update-verifier" / name).read_bytes(), data)
            self.assertEqual((self.resources / name).read_bytes(), data)
        override = json.loads((self.output / "tauri-update-resources.json").read_text())
        self.assertEqual(set(override["bundle"]["resources"].values()), {
            "update-verifier/gpgv", "update-verifier/trusted.gpg", "update-verifier/dependency.so",
        })

    def test_absent_input_does_not_create_trust(self):
        try:
            result = stage_update_trust.stage(None, None, self.output)
        except ValueError as error:
            self.fail(f"absent trust must remain unconfigured: {error}")
        self.assertIsNone(result)
        self.assertFalse(self.output.exists())

    def test_hash_mismatch_preserves_existing_output(self):
        (self.resources / "gpgv").write_bytes(b"changed verifier")
        self.assert_preserved_failure()

    def test_duplicate_unknown_and_nonobject_trust_are_rejected(self):
        for data in ('{"schema_version":1,"schema_version":1}', '[]'):
            with self.subTest(data=data):
                self.record.write_text(data)
                self.assert_preserved_failure()
        self.trust["unknown"] = True
        self.record.write_text(json.dumps(self.trust))
        self.assert_preserved_failure()

    def test_unsafe_repeated_or_unpinned_file_names_are_rejected(self):
        for key, value in (("verifier_file", "../gpgv"), ("verifier_file", "absent"), ("keyring_file", "gpgv")):
            with self.subTest(field=key, value=value):
                changed = dict(self.trust, **{key: value})
                self.record.write_text(json.dumps(changed))
                self.assert_preserved_failure()
        self.trust["files"].append(self.trust["files"][0])
        self.record.write_text(json.dumps(self.trust))
        self.assert_preserved_failure()

    def test_symlinked_trust_resource_or_resource_directory_is_rejected(self):
        for kind in ("record", "file", "directory"):
            with self.subTest(input=kind):
                if kind == "record":
                    alias = self.root / "alias-record"
                    alias.symlink_to(self.record)
                    self.record = alias
                elif kind == "file":
                    self.record = self.root / "approved-trust.json"
                    outside = self.root / "outside"
                    path = self.resources / "gpgv"
                    path.rename(outside)
                    path.symlink_to(outside)
                else:
                    (self.resources / "gpgv").unlink()
                    (self.root / "outside").rename(self.resources / "gpgv")
                    alias = self.root / "alias-input"
                    alias.symlink_to(self.resources, target_is_directory=True)
                    self.resources = alias
                self.assert_preserved_failure()

    def test_missing_or_nonregular_resource_preserves_output(self):
        path = self.resources / "gpgv"
        path.unlink()
        self.assert_preserved_failure()
        path.mkdir()
        self.assert_preserved_failure()

    def test_output_cannot_replace_or_contain_original_inputs(self):
        for kind in ("resources", "ancestor", "record", "inside-resources"):
            with self.subTest(output=kind), tempfile.TemporaryDirectory(prefix="stage-overlap-") as directory:
                root=Path(directory)
                resources=root / "input"
                resources.mkdir()
                for source in self.resources.iterdir():
                    (resources / source.name).write_bytes(source.read_bytes())
                record=root / "trust.json"
                record.write_bytes(self.record.read_bytes())
                outputs={"resources":resources,"ancestor":root,"record":record,"inside-resources":resources / "staged"}
                rejected=False
                try:
                    stage_update_trust.stage(record,resources,outputs[kind])
                except ValueError:
                    rejected=True
                self.assertTrue(record.is_file(), "original trust input was replaced")
                self.assertEqual(record.read_bytes(),self.record.read_bytes())
                for source in self.resources.iterdir():
                    original=resources / source.name
                    self.assertTrue(original.is_file(), "original resource input was replaced")
                    self.assertEqual(original.read_bytes(),source.read_bytes())
                self.assertTrue(rejected, "overlapping output was accepted")

    def test_existing_directory_output_is_preserved_for_valid_inputs(self):
        self.output.mkdir()
        sentinel = self.output / "unrelated-original"
        sentinel.write_bytes(b"keep original directory contents")
        rejected=False
        try:
            self.stage()
        except ValueError:
            rejected=True
        self.assertTrue(sentinel.is_file(), "existing directory contents were deleted")
        self.assertEqual(sentinel.read_bytes(), b"keep original directory contents")
        self.assertTrue(rejected, "pre-existing directory output must be refused")

    def test_existing_regular_file_output_is_preserved(self):
        self.output.write_bytes(b"previous output file")
        with self.assertRaises(ValueError):
            self.stage()
        self.assertTrue(self.output.is_file(), "failed stage replaced existing output")
        self.assertEqual(self.output.read_bytes(), b"previous output file")

    def test_explicit_https_authority_is_required(self):
        for repository in ("https:source.invalid/project", "https:///source.invalid/project", "https://user:password@source.invalid/project"):
            with self.subTest(repository=repository):
                self.trust["source_repository"] = repository
                self.record.write_text(json.dumps(self.trust))
                self.assert_preserved_failure()


if __name__ == "__main__":
    unittest.main(verbosity=2)
