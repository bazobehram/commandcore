# Permissions

CommandCore permissions are explicit policy, not accidental OS failures.

## Profiles

### READ_ONLY

Inspection only: device info, filesystem read/list/search/stat, process/system inspection, downloads, and native Git read operations.

### STANDARD

READ_ONLY plus filesystem mutation, shell/process control, upload and `git.run`, executing as the unprivileged Agent OS account.

### FULL_CONTROL

STANDARD plus execution through the privileged helper and Linux service/package/power controls. All Docker tools require FULL_CONTROL because Docker daemon access is root-equivalent on normal Linux installations.

## Four-way authority intersection

For OAuth clients, effective authority is the minimum of:

```text
OAuth scope
per-device subject grant
server device profile
device-local maximum/helper availability
```

Bootstrap/panel admin bypasses the OAuth-scope layer but does not bypass server profile or device-local maximum.

## Local maximum

`/etc/commandcore/agent-policy.json` is root-owned and defines the highest profile a device accepts. The control plane cannot remotely exceed it. FULL_CONTROL additionally requires a healthy authenticated root helper.
