# Local observable AI work timeline

This document describes the source candidate following RC6, not a replacement for
the immutable published RC6/RC6.1 artifacts. The timeline uses the existing Linux
user service journal. Windows journal viewing remains unsupported.

```sh
commandcore-agent activity
commandcore-agent activity --json
commandcore-agent activity --last 100
commandcore-agent activity --errors
commandcore-agent activity --service commandcore-agent-canary.service
```

The default follows live events as UTC timestamped REQUEST, RESULT and CONNECTION
blocks with pretty JSON. `--json` produces one redacted JSON object per line.
`--last` reads recent journal entries and exits. Unstructured historical debug
messages are ignored. Requests and results share both the protocol request ID and
execution ID; concurrent work can interleave without losing correlation.

Requests show exact sanitized commands, effective cwd, file/source/destination
paths, offsets, lengths, timeout, script/process arguments, and source/client
information when the server supplies it. Results show operation status, process
ID, exit code, duration, returned/written bytes, change status, and bounded text
previews. Shell streams are collected across chunk boundaries before redaction,
then shown in the final RESULT. For long managed jobs, `process.output` requests
show the output returned by that poll. Connection and retry events are separate
from execution results; interrupted requests receive a closing cancellation event.

An operator can reconstruct this sequence from the terminal:

1. Write `config.py` (path and byte count).
2. Read `config.py` (path, bytes and `value = 1` preview).
3. Write `check_config.py` (path and byte count).
4. Run Python `check_config.py` in the workspace; observe configuration/test output.
5. Patch `config.py` (one patch, changed result).
6. Read the updated `value = 2`.
7. Repeat the Python check and observe exit code zero and tests passing.

## Redaction boundary

Python and Rust share `activity_policy.json`. Agents sanitize objects **before**
writing structured events to the journal; viewers apply the same policy again
before rendering. Server audit storage retains its separate metadata-only policy.
The wire requests, wire results and execution permissions are unchanged.

- Only reviewed contextual fields are retained; unknown payload fields are omitted.
- Known device credentials/private keys, secret environment values and supplied
  environment values are masked wherever they recur in text.
- Credential assignments, secret flags, auth/cookie headers, URL credentials,
  private-key blocks and long encoded values are redacted. Ordinary commands,
  including `python -u`, and ordinary paths remain readable.
- `fs.write` emits byte counts, not content. Patches emit counts, not replacement
  text. Keyboard typing, clipboard and transfer payloads are metadata-only.
- `fs.read` suppresses encoded/binary previews and previews of recognized sensitive
  paths such as `.env`, SSH keys, credential files and Agent state.
- Text fields retain at most 2,048 characters with a truncation marker; output
  counts describe original streamed bytes. Stream collection holds at most 16,384
  characters per stream. Total structured events are bounded to 16 KiB; oversized
  context fields are replaced with a bounded-field marker.
- ANSI/control characters are removed and string contents are JSON escaped.

Redaction cannot infer that an arbitrary short, unlabelled string in an otherwise
ordinary text file is a secret. Sensitive data must be recognizable through its
field, path, credential format or registered value. Local journal access and
retention remain controlled by the operating system; text previews can contain
ordinary private project information.

## Disposable acceptance

`tests/test_local_activity.py` exercises the actual Python request handler with
disposable file reads/patches and subprocess execution. Rust activity tests execute
the same file/edit/command pipeline through the actual executor. Redaction tests
cover both render formats, split output, byte counts, sensitive payloads, long
paths and useful commands. `scripts/local_activity_fixture.py` supplies a bounded
local workload suitable for an isolated user service; it does not enroll a device
or connect to a production server.
