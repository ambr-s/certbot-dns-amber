"""Check the installed image without credentials, network or source mounts."""

import subprocess
import sys


def run(image, *args, entrypoint=None):
    command = ["docker", "run", "--rm", "--network", "none"]
    if entrypoint:
        command.extend(["--entrypoint", entrypoint])
    result = subprocess.run(
        [*command, image, *args], check=True, text=True, capture_output=True
    )
    print(result.stdout, end="")
    return result.stdout


def main(image):
    run(image, "--version")
    plugins = run(image, "plugins", "--authenticators")
    sections = plugins.split("* ")
    if not any(
        section.startswith("dns-amber\n") and "Authenticator" in section
        for section in sections
    ):
        raise SystemExit("dns-amber was not discovered as an authenticator")
    help_text = run(image, "--help", "dns-amber")
    for option in ("--dns-amber-credentials", "--dns-amber-state-dir"):
        if option not in help_text:
            raise SystemExit(f"Missing plugin option: {option}")
    run(image, "-m", "pip", "check", entrypoint="python")
    run(image, "-m", "certbot_dns_amber", "recover", "--help", entrypoint="python")


if __name__ == "__main__":
    main(sys.argv[1])
