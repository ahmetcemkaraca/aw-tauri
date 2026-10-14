"""Stage approved build inputs; configured builds require Python 3, runtime does not."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from urllib.parse import urlsplit

ERROR = "Update verification resources are unavailable or invalid"
FIELDS = {"schema_version", "manifest_signer_fingerprint", "source_repository", "channel", "verifier_file", "keyring_file", "files"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(ERROR)
        result[key] = value
    return result


def regular_input(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError(ERROR)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    stream = os.fdopen(descriptor, "rb")
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        stream.close()
        raise ValueError(ERROR)
    return stream


def read_trust(path):
    try:
        with regular_input(Path(path), 64_000) as stream:
            data = stream.read(64_001)
        if len(data) > 64_000:
            raise ValueError(ERROR)
        record = json.loads(data, object_pairs_hook=unique_object)
        if not isinstance(record, dict) or set(record) != FIELDS or type(record["schema_version"]) is not int or record["schema_version"] != 1:
            raise ValueError(ERROR)
        fingerprint = record["manifest_signer_fingerprint"]
        if not isinstance(fingerprint, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", fingerprint):
            raise ValueError(ERROR)
        repository = record["source_repository"]
        if not isinstance(repository, str) or not repository.startswith("https://") or any(ord(c) <= 32 or ord(c) == 127 for c in repository):
            raise ValueError(ERROR)
        parsed = urlsplit(repository)
        if not parsed.netloc or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or "\\" in parsed.netloc:
            raise ValueError(ERROR)
        if record["channel"] not in ("stable", "beta", "preview"):
            raise ValueError(ERROR)
        files = record["files"]
        if not isinstance(files, list) or not files:
            raise ValueError(ERROR)
        names = set()
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"name", "sha256"}:
                raise ValueError(ERROR)
            name, digest = entry["name"], entry["sha256"]
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", name) or name in names:
                raise ValueError(ERROR)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(ERROR)
            names.add(name)
        if not isinstance(record["verifier_file"], str) or not isinstance(record["keyring_file"], str) or record["verifier_file"] == record["keyring_file"]:
            raise ValueError(ERROR)
        if record["verifier_file"] not in names or record["keyring_file"] not in names:
            raise ValueError(ERROR)
        return data, record
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError(ERROR) from error


def stage(trust_file, resources, output):
    if trust_file is None:
        return None
    try:
        output = Path(output)
        resources = Path(resources)
        data, record = read_trust(trust_file)
        if resources.is_symlink() or not resources.is_dir() or output.is_symlink() or output.exists():
            raise ValueError(ERROR)
        destination = output.resolve()
        source_directory = resources.resolve()
        source_record = Path(trust_file).resolve()
        if (destination == source_directory or destination in source_directory.parents
                or source_directory in destination.parents or destination == source_record
                or destination in source_record.parents):
            raise ValueError(ERROR)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".update-stage-", dir=output.parent) as directory:
            staged = Path(directory)
            helper = staged / "update-verifier"
            helper.mkdir(mode=0o700)
            for entry in record["files"]:
                limit = 1024 * 1024 if entry["name"] == record["keyring_file"] else 64 * 1024 * 1024
                digest = hashlib.sha256()
                size = 0
                destination = helper / entry["name"]
                with regular_input(resources / entry["name"], limit) as source, destination.open("xb") as copied:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > limit:
                            raise ValueError(ERROR)
                        digest.update(chunk)
                        copied.write(chunk)
                if digest.hexdigest() != entry["sha256"]:
                    raise ValueError(ERROR)
                copied_digest = hashlib.sha256()
                with destination.open("rb") as copied:
                    while chunk := copied.read(1024 * 1024):
                        copied_digest.update(chunk)
                if copied_digest.hexdigest() != entry["sha256"]:
                    raise ValueError(ERROR)
                destination.chmod(0o700 if entry["name"] == record["verifier_file"] else 0o600)
            (staged / "release-trust.json").write_bytes(data)
            override = {"bundle": {"resources": {
                str(output.absolute() / "update-verifier" / entry["name"]): "update-verifier/" + entry["name"]
                for entry in record["files"]
            }}}
            (staged / "tauri-update-resources.json").write_text(json.dumps(override, indent=2) + "\n", encoding="utf-8")
            output.mkdir(mode=0o700)
            try:
                # Publish trust last so configured builds only see a complete resource set.
                for name in ("update-verifier", "tauri-update-resources.json", "release-trust.json"):
                    (staged / name).rename(output / name)
            except OSError:
                shutil.rmtree(output)
                raise
        return output / "release-trust.json"
    except (OSError, TypeError, ValueError) as error:
        raise ValueError(ERROR) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", type=Path)
    parser.add_argument("--trust-file", type=Path)
    parser.add_argument("--resources", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.validate_only is not None:
            _, record = read_trust(arguments.validate_only)
            for entry in record["files"]:
                print(entry["name"])
        else:
            if arguments.output is None or (arguments.trust_file is not None and arguments.resources is None):
                parser.error("--output and configured --resources are required")
            result = stage(arguments.trust_file, arguments.resources, arguments.output)
            print("not-configured" if result is None else str(result))
    except ValueError:
        parser.exit(1, ERROR + "\n")


if __name__ == "__main__":
    main()
