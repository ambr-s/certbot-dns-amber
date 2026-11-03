"""Verify Docker's real context filtering using synthetic files, never secrets.

Requires Docker with BuildKit/buildx. Mirrors tracked paths in an isolated temp
context, copies only the real .dockerignore rules, and exports COPY . from a
scratch image. The expected file set is independent of the ignore patterns.
"""

from pathlib import Path
import subprocess
import tempfile


EXPECTED = {
    ".dockerignore",
    "Dockerfile",
    "README.md",
    "pyproject.toml",
    "src/certbot_dns_amber/__init__.py",
    "src/certbot_dns_amber/__main__.py",
    "src/certbot_dns_amber/authenticator.py",
    "src/certbot_dns_amber/client.py",
    "src/certbot_dns_amber/core.py",
}
PROBES = {
    "src/certbot_dns_amber/amber-credentials.json",
    "src/certbot_dns_amber/private/amber-credentials.json",
    "src/certbot_dns_amber/new_module.py",
    "src/certbot_dns_amber/__pycache__/core.cpython-312.pyc",
    "src/unrelated/module.py",
    ".env",
    ".git/config",
    "dist/package.whl",
}


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True,
        text=True,
    ).stdout.rstrip("\0").split("\0")
    missing = sorted(path for path in EXPECTED if not (root / path).is_file())
    if missing:
        raise SystemExit(f"Missing runtime inputs in checkout: {missing}")
    with tempfile.TemporaryDirectory(prefix="amber-context-") as temporary:
        context = Path(temporary) / "context"
        exported = Path(temporary) / "exported"
        context.mkdir()
        for name in set(tracked) | EXPECTED | PROBES:
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SYNTHETIC TEST DATA ONLY\n")
        (context / ".dockerignore").write_bytes((root / ".dockerignore").read_bytes())
        # stdin avoids changing the runtime Dockerfile path or introducing a
        # Dockerfile-specific ignore file that could override .dockerignore.
        subprocess.run(
            [
                "docker", "buildx", "build", "--no-cache", "--network=none",
                "--progress=plain", "--file", "-", "--output",
                f"type=local,dest={exported}", str(context),
            ],
            input="FROM scratch\nCOPY . /\n", text=True, check=True,
        )
        actual = {
            path.relative_to(exported).as_posix()
            for path in exported.rglob("*") if not path.is_dir()
        }
        print("Exported context files:", *sorted(actual), sep="\n  ", flush=True)
        unexpected = sorted(actual - EXPECTED)
        missing = sorted(EXPECTED - actual)
        if unexpected or missing:
            raise SystemExit(
                f"FAIL: Docker context allowlist mismatch\n"
                f"Unexpected: {unexpected}\nMissing: {missing}"
            )
        print(f"PASS: Docker context contains exactly {len(EXPECTED)} allowed files; "
              f"all {len(PROBES)} synthetic probes excluded.")


if __name__ == "__main__":
    main()
