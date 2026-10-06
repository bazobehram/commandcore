# Linux privileged helper

Status: **IMPLEMENTED; Linux FULL_CONTROL candidate in 0.9.0-rc7**.

`commandcore-helper` is the Linux privilege-separated execution service for devices whose root-owned local policy permits `FULL_CONTROL`. The network-facing Agent remains a dedicated unprivileged service and reaches the helper only through a local Unix socket; the helper exposes no TCP/HTTP listener.

## Local trust boundary

Default paths:

```text
/etc/commandcore/agent-policy.json
/etc/commandcore/helper.key
/run/commandcore/helper.sock
/var/log/commandcore/helper-audit.jsonl
```

Requests are checked with Linux `SO_PEERCRED`, HMAC-SHA256, timestamp freshness, nonce replay rejection and root-owned local policy. The socket is group-restricted; the runtime directory is only traversable as needed.

The same root-owned Agent policy can contain the trusted update release public key and allowed HTTPS manifest origins. The control plane can discover only a boolean trust-readiness capability; it cannot read/change the private authority or choose arbitrary update hosts.

## Install modes

```bash
sudo ./agent/install-linux.sh --max-profile READ_ONLY
sudo ./agent/install-linux.sh --max-profile STANDARD
sudo ./agent/install-linux.sh --max-profile FULL_CONTROL
```

FULL_CONTROL enables the helper while leaving the Agent unprivileged. Fleet update devices additionally need locally configured signed-update trust.

## FULL_CONTROL semantics

Ordinary filesystem/shell/process/system/transfer operations may be delegated through the helper as root; services, packages, power, Docker and Agent update mutation are FULL_CONTROL operations. This is intentionally powerful administration, not a sandbox.

## Local enable and disable

After installing the separately reviewed root-owned helper runtime, use:

```bash
sudo commandcore-agent enable-full-control --agent-user commandcore
sudo commandcore-agent disable-full-control
```

Enable requires a local typed acknowledgement. Local automation can explicitly
use `--acknowledge-root-access`. The helper runtime, policy, secret and parent
directories must be protected from the network Agent. A failed authenticated
helper health check leaves the ceiling STANDARD. Disable lowers the policy before
stopping the service. Existing signing trust and identity are retained; these
commands never create or raise a server grant. Restart the network Agent to update
its advertised capabilities. The Rust CLI forwards only to the protected stable
Python helper runtime. Windows helper support is not available.

The user installer intentionally does not install privileged code. A missing
root runtime is a clear refusal; an unverified user-owned executable is never
started as a root service. Container acceptance used an actual root helper and
unprivileged Agent with a systemd lifecycle shim; it does not establish real
systemd install/upgrade acceptance.
