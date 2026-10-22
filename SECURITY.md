# Security

whatdoesthisboxdo logs in to servers and reads almost everything on them, so it
handles sensitive data in both directions. What it does with it:

## Credentials it stores

- **The web app's saved credentials** (SSH passwords, keys, vCenter, Proxmox,
  GitLab and Harbor tokens) are encrypted with Fernet (`cryptography`) before they
  reach the database. `cryptography` is required; there is no plaintext fallback.
  Values saved by older versions as `b64:` are still readable and are encrypted
  the next time they are saved.
- **The encryption key** is `ENCRYPTION_KEY` from the environment, or, for a
  local SQLite install, a random key generated once in `web/data/.encryption_key`
  (mode 600). Anyone with the key and the database can read every credential, so
  back them up separately.
- **The session key** is `SECRET_KEY`, or a random key generated once in
  `web/data/.secret_key`. Docker Compose refuses to start without `SECRET_KEY`,
  `ENCRYPTION_KEY` and `POSTGRES_PASSWORD`; there are no default secrets.

## What it collects

`scripts/collect_system_state.sh` is meant for recreating a box, so it copies
users' SSH private keys and exports GPG secret keys into its output folder.
Treat that output as you would the server's own disk: don't commit it, share it
or leave it on a shared drive. The analyzer's output (configs, bash history,
environment) can contain secrets too.

## Connections

- **SSH host keys** are trusted on first use and recorded in
  `~/.whatdoesthisboxdo/known_hosts` (`SSH_KNOWN_HOSTS`), on top of the system's
  `known_hosts`. A host whose key changes is refused. Delete its line to accept
  an expected change.
- **Proxmox TLS** is verified by default. `PROXMOX_VERIFY_SSL=false` turns that
  off, for a lab with Proxmox's self-signed certificate.

## Reporting a problem

Please report security issues privately through GitHub's "Report a
vulnerability" (Security tab), not as a public issue.
