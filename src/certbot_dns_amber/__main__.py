"""Explicit abandoned-challenge cleanup, using only retained command identities."""

import argparse
import sys
from types import SimpleNamespace

from certbot.errors import PluginError

from .authenticator import Authenticator
from .client import DEFAULT_ENDPOINT


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["recover"])
    parser.add_argument("--credentials", required=True)
    parser.add_argument(
        "--state-dir",
        required=True,
        help="Absolute path to the existing persistent private journal directory.",
    )
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--confirm-no-active-certbot",
        action="store_true",
        required=True,
        help="Confirm all Certbot jobs using this journal are stopped; cleanup affects every retained challenge.",
    )
    args = parser.parse_args(argv)
    config = SimpleNamespace(
        dns_amber_credentials=args.credentials,
        dns_amber_state_dir=args.state_dir,
        dns_amber_endpoint=args.endpoint,
        dns_amber_propagation_seconds=60,
    )
    try:
        auth = Authenticator(config, "dns-amber")
        auth._setup_credentials()
        auth.engine.recover()
    except PluginError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Retained challenges cleaned up; this is not public DNS removal proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
