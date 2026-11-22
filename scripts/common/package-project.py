"""Create a source-and-evidence submission snapshot using only the standard library."""
import argparse
import datetime
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = ("apps", "monitoring", "deploy", "scripts", "tests", "docs", "security", "evidence")
ROOT_FILES = ("README.md", ".gitignore")
ALLOWED_SUFFIXES = {".py", ".sh", ".txt", ".md", ".json", ".jsonl", ".log", ".yaml", ".yml", ".args", ".service", ".timer", ".socket", ".sha256", ".utc", ".pdf", ".png", ".csv", ".tsv", ".xml", ".html", ".svg", ".conf", ".sieve", ".mmd"}
ALLOWED_NAMES = {"Dockerfile", ".dockerignore", ".gitignore", "README.md"}
PRIVATE_NAMES = {".env", "kubeconfig", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts"}
PRIVATE_MARKERS = ("password", "secret", "credential", "token")


def source_files():
    files = [ROOT / name for name in ROOT_FILES]
    for name in DIRECTORIES:
        directory = ROOT / name
        if not directory.is_dir():
            raise RuntimeError("Required source directory is missing: " + name)
        files.extend(directory.rglob("*"))
    selected = []
    for path in files:
        if path.is_symlink():
            raise RuntimeError("Submission paths must not be symbolic links: " + str(path))
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in {".venv", "__pycache__", ".git", "backups", "archive", "results"} for part in rel.parts):
            continue
        if (path.name in PRIVATE_NAMES or path.name.startswith(".env.")
                or any(marker in path.name.lower() for marker in PRIVATE_MARKERS)):
            continue
        evidence_context = rel.parts[0] == 'evidence' and path.name == 'build-context.tar.gz'
        if path.name not in ALLOWED_NAMES and path.suffix not in ALLOWED_SUFFIXES and not evidence_context:
            continue
        selected.append(path)
    return sorted(set(selected), key=lambda p: p.relative_to(ROOT).as_posix())


def write_member(archive, name, content, mode):
    info = tarfile.TarInfo("security-monitoring-platform/" + name)
    info.size = len(content)
    info.mode = mode
    archive.addfile(info, io.BytesIO(content))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New .tar.gz path; existing files are never overwritten")
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = args.output or ROOT.parent / ("security-monitoring-platform-" + stamp + ".tar.gz")
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "scope": "Curated project source and retained final evidence; report supplied separately",
                "excluded": ["archives and backups", "image archives", "databases", "virtual environments", "private credential files"],
                "files": []}
    files = source_files()
    # Assemble the contents before creating the final destination.
    with tempfile.TemporaryFile(dir=destination.parent) as temporary:
        with tarfile.open(fileobj=temporary, mode="w:gz") as archive:
            for path in files:
                rel = path.relative_to(ROOT).as_posix()
                content = path.read_bytes()
                write_member(archive, rel, content, 0o755 if path.suffix == ".sh" else 0o644)
                manifest["files"].append({"path": rel, "bytes": len(content),
                                         "sha256": hashlib.sha256(content).hexdigest()})
            write_member(archive, "MANIFEST.json",
                         (json.dumps(manifest, indent=2) + "\n").encode(), 0o644)
        temporary.seek(0)
        output = destination.open("xb")
        try:
            with output:
                while chunk := temporary.read(1024 * 1024):
                    output.write(chunk)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    print(destination)
    print("Included files: " + str(len(manifest["files"])))
    print("Archive bytes: " + str(destination.stat().st_size))
    print("SHA256: " + hashlib.sha256(destination.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
