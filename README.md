# certbot-dns-amber

Standalone Certbot DNS-01 authenticator for the **amber.systems console API**, not
Bunny or Cloudflare provider credentials. Linux/POSIX only (uses `flock`, atomic
rename and directory `fsync`). Python 3.10+, Certbot 2.11–5.x. Install into the
**same Python environment as Certbot**; a system/snap Certbot does not discover
plugins installed into an unrelated virtual environment.

Requires the scoped DNS restrictions and durable create-result contract described
in [the console API](https://github.com/ambr-s/console/blob/main/docs/api.md), including migration 038. No console
TypeScript runtime changes are required.

## Install and configure

From this directory in a trusted checkout:

```sh
python3 -m venv /opt/certbot-amber
/opt/certbot-amber/bin/python -m pip install .
/opt/certbot-amber/bin/certbot plugins --authenticators
```

The registered authenticator is `dns-amber`. Keep package upgrades deliberate;
use your normal dependency pinning and vulnerability-management process.

Create a private directory under a trusted, non-world-writable parent. Store the
following JSON in `/etc/letsencrypt/amber-credentials.json`, owned by the account
running Certbot, mode **0600** (0400 is also accepted). Do not put the token in a
command line, URL, shell history, source control or logs. Symlinked credential
files are rejected. Use the console's **local canonical zone UUID**, not a provider
ID. Zone names are lowercase ASCII/punycode without a trailing dot.

```json
{
  "token": "REPLACE_PRIVATELY_WITH_SCOPED_CONSOLE_TOKEN",
  "zones": {
    "example.com": "59ade904-17bc-4e76-9c7e-a0fead90db67",
    "example.net": "710864e6-3a56-4fa9-b0ce-3b2ed878b7ab"
  }
}
```

Explicit mappings avoid broad inventory discovery. The longest matching zone
wins at DNS label boundaries, and an exact-zone GET verifies its ID and domain
before a new command. This does not follow CNAME delegations automatically. For
an NS-delegated challenge zone, map that actual zone explicitly. Do not configure
zones that do not host the validation owner.

### Least-privilege token

Issue the token through an authorised **session**, not through this plugin. Use
an organisation binding and a future expiry within the console's 90-day maximum.
The issuer needs persistent authority, not temporary support access. For an apex
and wildcard certificate for `example.com`, the scope portion is:

```json
{
  "scopes": [
    "dns.zones.read", "dns.records.read",
    "dns.records.create", "dns.records.delete"
  ],
  "dnsRestrictions": [{
    "zoneId": "59ade904-17bc-4e76-9c7e-a0fead90db67",
    "scopes": [
      "dns.zones.read", "dns.records.read",
      "dns.records.create", "dns.records.delete"
    ],
    "name": "_acme-challenge",
    "recordTypes": ["TXT"]
  }]
}
```

This is only the scope portion, not a complete key-issuance request. Add exact
rules for `_acme-challenge.www` when validating `www.example.com`, and separate
rules for each other zone. Leave `includeSubdomains` absent/false unless you
actually need descendants. Do not grant update, zone/key administration,
nameserver, assignment or operation-review scopes. `*` in a restriction is a
literal DNS wildcard, not a permission glob. An apex and wildcard validation can
have **different TXT values at the same owner**; the plugin creates separate
records and tracks their separate opaque IDs.

### Certificate issuance (operator action; performs real DNS writes)

```sh
/opt/certbot-amber/bin/certbot certonly \
  --authenticator dns-amber \
  --dns-amber-credentials /etc/letsencrypt/amber-credentials.json \
  --dns-amber-state-dir /etc/letsencrypt/dns-amber \
  --dns-amber-propagation-seconds 60 \
  -d example.com -d '*.example.com'
```

The default API origin is `https://console.amber.systems`; an alternate console
can be supplied with `--dns-amber-endpoint https://your-console.example`. Only
verified HTTPS origins are accepted. Redirects are rejected. Environment proxy,
netrc and CA overrides are disabled; the Requests trust store is used. Connect
and read-idle timeouts are 10 and 30 seconds; these are not a total wall-clock
deadline. There are no automatic HTTP retries and no insecure mode.

The propagation default is **60 seconds**, configurable with Certbot's option.
It is a delay, **not proof of public DNS propagation**. Verify authoritative DNS
and delegation independently when diagnosing validation failures. Console
success describes provider command acknowledgement, not worldwide TXT visibility.

## Container deployment (GHCR)

After this workflow is merged and succeeds on `main`, the image is published to
`ghcr.io/ambr-s/certbot-dns-amber:latest` and `:sha-<full-commit-sha>` (Linux amd64).
Prefer a commit tag or digest for deliberate upgrades. Publication does not make
this repository or its package public: authenticate Docker to GHCR with an account
that has package read access when required. No image is published from a PR or a
manual run on another branch.

The image includes Python 3.12, Certbot and this plugin. Its entrypoint is
`certbot`; pass Certbot arguments directly. No credentials are built into it.
Create the host state directory on local persistent storage and prepare the
credential file described above separately, owned by root with mode 0600 (0400
also works). The image runs as root; for rootless Docker, use the corresponding
mapped host owner. Never put tokens in build arguments or environment variables.

```sh
sudo install -d -m 0700 /srv/certbot-amber/letsencrypt
# Securely provision /srv/certbot-amber/amber-credentials.json before running.
# This issuance command performs real DNS writes:
docker run --rm -it \
  --mount type=bind,src=/srv/certbot-amber/letsencrypt,dst=/etc/letsencrypt \
  --mount type=bind,src=/srv/certbot-amber/amber-credentials.json,dst=/run/amber-credentials.json,readonly \
  ghcr.io/ambr-s/certbot-dns-amber:latest certonly \
  --authenticator dns-amber \
  --dns-amber-credentials /run/amber-credentials.json \
  --dns-amber-state-dir /etc/letsencrypt/dns-amber \
  --dns-amber-propagation-seconds 60 \
  -d example.com -d '*.example.com'
```

The `/etc/letsencrypt` bind mount retains accounts, certificates, renewal
configuration **and the plugin journal** across container removal. Keep this same
mount and the same read-only credential path for every renewal/recovery command;
never use ephemeral state or a separate journal for another job. Back it up
securely and never run overlapping jobs. To renew, use the same `docker run`
mounts, omit `-it`, and replace `certonly` and its options with `renew`.
Schedule that command on the host; the image does not contain a scheduler.
`renew --dry-run` still performs real DNS writes. Work files and logs are ephemeral
unless you also mount `/var/lib/letsencrypt` and `/var/log/letsencrypt`.

For explicit recovery, stop all scheduled jobs and use those same mounts with
`docker run --entrypoint python ... IMAGE -m certbot_dns_amber recover
--credentials /run/amber-credentials.json --state-dir /etc/letsencrypt/dns-amber
--confirm-no-active-certbot`. The recovery safety rules below still apply.

Local build and credential-free runtime verification:

```sh
docker build --pull -t certbot-dns-amber:local .
python3 scripts/smoke-container.py certbot-dns-amber:local
```

CI retains the pytest, package build and installed-wheel discovery gates, then
builds and smoke-tests the container with networking disabled. Only main pushes
and manual main runs can hand the tested image to a separate GHCR publisher
using `GITHUB_TOKEN`; only that job has `packages: write`. The publisher loads the
same image, without rebuilding. The short-lived image artifact is only an internal
transfer, not a wheel release. The Docker context is an explicit file allowlist;
new runtime source files must be added to `.dockerignore` deliberately.

## Renewal, expiry and rotation

Certbot saves the plugin options in its renewal configuration. Keep the same
absolute credential path and the **same persistent state directory** for renewal
and recovery. Both `--dns-amber-state-dir` and recovery's `--state-dir` require
an **absolute path**. Relative paths are rejected, not resolved against the current
working directory, so changing directories cannot bypass retained journals.
The default state directory is `<Certbot config-dir>/dns-amber` and must also be
absolute.
Use one journal for all this installation's jobs, not ephemeral/container-local
storage, separate per-run directories or network filesystems. Do not run two
hosts against the same credentials and independent journals.

Schedule token rotation **before expiry**, independently of certificate renewal.
From the same issuer's authorised session, issue a replacement with the same
organisation, zone/name/TXT restrictions and four scopes. Resolve outstanding commands **with the original token before rotation/revocation**.
Restricted replay is bound to the **credential ID as well as actor**, zone,
intent, payload and UUID (`performDnsRecordMutation` includes `credential_id` in
its journal payload). A replacement key, even from the same issuer with identical
scopes, cannot replay an old create or DELETE. Current grants and restrictions
are also rechecked. Once all old challenges are cleaned up, atomically replace
the credentials JSON at its existing path, retaining owner and 0600 permissions,
then revoke the old key. Do not broaden permissions to force recovery.

If a key expires or is revoked with `creating`/`deleting` entries outstanding,
keep the journal and obtain authorised operator assistance: credential rotation
alone cannot recover those UUIDs. A confirmed `created` entry with no DELETE
attempt can be cleaned up using a replacement key that is permitted to delete
that exact record; its first DELETE receives its own persisted UUID. Any failure
still retains the state, never implies success.

`certbot renew --dry-run` uses staging ACME but **still performs real DNS writes**;
run it only when authorised. No real credentials or DNS writes are needed for the
package's tests below.

## Durable recovery and safety

The journal directory must be owned by the running user, mode 0700, under trusted
ancestors; journal/lock files are 0600. Every command holds a nonblocking local
process lock. Atomic writes fsync both the file and directory. A checksum catches
accidental journal edits; it is not protection against a malicious same-user or
root process. Back up the state securely: it contains TXT values and opaque
handles, though never bearer tokens. Preserve the whole journal, including
completed tombstones. Do not edit, delete, truncate, roll back or relocate it to
bypass uncertainty. Loss of all state cannot be recovered automatically.

Before POST, the plugin persists the original UUID and exact `Type: 3`, relative
`Name`, case-sensitive `Value`, and `Ttl: 60` payload. A lost create response can
only replay that same UUID/payload. Invalid/missing results, `result_unavailable`,
conflicts and transport failures retain `creating`. New creates are blocked while
any entry is `creating` or `deleting`; this deliberately includes rejected writes
until safely resolved. A record is never searched for, adopted or deleted by TXT
match. No update operation is used.

Create success retains the opaque `Id` and original `Revision`. Cleanup first
persists a **separate delete UUID**, then DELETEs that exact ID with the original
baseline. It never refreshes a baseline or substitutes another record. 404 is
**never success**. A missing/edited record, lost delete reply or revoked permission
leaves `deleting` until the same DELETE is confirmed, or an authorised operator
resolves the situation. No observation route or absence inference is used.

After a crash, stop all Certbot jobs sharing the journal (including timers), then
explicitly request cleanup of **all retained, unfinished challenges**:

```sh
/opt/certbot-amber/bin/python -m certbot_dns_amber recover \
  --credentials /etc/letsencrypt/amber-credentials.json \
  --state-dir /etc/letsencrypt/dns-amber \
  --confirm-no-active-certbot
```

This is a mutating recovery command: it may replay an original create before
deleting its returned handle. If the initial request never reached the console,
that replay may perform the original create once. If the console reports an
uncertain/failed operation or unavailable result, recovery stops, preserves the
journal and requires operator assistance. It never mints a new create UUID.
Malformed/corrupt state also stops before network I/O. Do not use recovery during
an active CA validation: a lock protects each command, not the propagation wait.

## Local verification

```sh
python -m pip install '.[test]'
python -m pytest -q
python -m build
# Install the built wheel into a fresh venv with Certbot, then:
certbot plugins --authenticators --config-dir "$PRIVATE_TEST_DIR/config" \
  --work-dir "$PRIVATE_TEST_DIR/work" --logs-dir "$PRIVATE_TEST_DIR/logs"
```

Tests cover crash/replay in separate processes against a loopback HTTP fixture,
exact stable UUIDs, delete baselines, multi-value/multi-zone isolation, secure
credentials, journal permissions/corruption, locking, HTTPS settings, redacted
failures and error envelopes. The loopback rewrite exists **only in tests**, not
in production configuration. These tests do not prove live provider behavior,
public propagation, ACME issuance or renewal. No live calls are made in CI.
