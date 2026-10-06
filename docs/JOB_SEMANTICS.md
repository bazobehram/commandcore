# Managed Linux job semantics

On Linux, managed jobs on an available systemd user manager run in a transient service named
from canonical device and job UUIDs. The supervisor claims its PID/start ticks,
boot ID and systemd invocation ID before starting the shell. Commands and
environment cross a private stdin pipe; they are not stored in unit arguments,
job metadata or Activity. The workload has `NoNewPrivileges=yes`, OOM adjustment
500, `OOMPolicy=kill`, and `KillMode=control-group`. There is no privileged helper.

The installer retains the existing Agent identity and user service. Jobs created by earlier Agent versions retain their existing metadata and supervision path; they are not rewritten during upgrade.
Non-systemd development environments retain independent process groups and report
`failure_domain=shared_parent_cgroup`. An installed CommandCore service refuses
to launch a new shared-cgroup job when its user bus is unavailable.

| Event | Behavior |
| --- | --- |
| Normal shell exit | Persist known exit code/time, `exited`; retrieve bounded output. Transient service cleanup ends remaining descendants after supervisor exit. |
| Explicit stop | Supervisor signals the original child group after checking start identity, escalates after three seconds; `stopped_by_request`. |
| MCP client disconnect | Managed workload continues; remote authorization is still checked on every new operation. |
| Network / server / WebSocket interruption | Workload continues locally; same process_id and files survive reconnection. |
| Agent restart / crash / targeted Agent OOM | Separate job service continues while the user manager remains alive; restarted Agent reconciles protected metadata. |
| Workload cgroup OOM | systemd ends that job cgroup; reconciled reason `workload_oom` when the original invocation's retained Result proves OOM. |
| Supervisor lost | `worker_lost` unless stronger unit evidence exists. Legacy surviving children are reported and require local reconciliation; remote stop does not claim success. |
| Host reboot | Workload ends; retained identity/output, `host_rebooted`; no automatic workload resume. |
| PID reused | PID + start ticks + boot ID prevent treating the replacement as the original job. No stop is sent to a reused identity. |
| Global OOM kills user manager | User services can all be removed. New jobs record manager identity and classify its disappearance as `user_manager_lost`. Root `user@UID.service Restart=no` requires another activation such as login. No default claim of automatic recovery from that parent failure. |

`completed_at` is known supervisor-observed completion time. When reconciliation
cannot establish completion time, it remains null and `reconciled_at` records
the observation instead. A surviving authorized workload never bypasses revoked
grants or the local permission ceiling.

## Output

Live request output uses a bounded 64-frame transport queue and chunks of at
most 8 KiB, applying backpressure rather than accumulating an unbounded queue
when the network stalls. Socket sends time out after 15 seconds; an otherwise
silent connection times out after 45 seconds. Authenticated heartbeat replies
are additive and ignored by legacy Python Agents. Foreground request processes
are cancelled on transport failure; durable managed jobs continue separately.
The existing server request-output byte cap remains in force. The response's
`output_capture` reports its combined stdout/stderr byte limit, observed and
retained bytes, truncation and whether the request transport finished normally.
It does not claim unseen output is complete after a connection failure.

Private per-job files retain at most **1 MiB stdout and 1 MiB stderr**. Excess is
drained and discarded. Per-stream capture metadata records observed bytes,
retained bytes, truncation, EOF completion and last output time. After abrupt
supervisor loss the counters are a lower bound and `complete=false`; absence of
legacy counters means truncation is unknown, not false. `complete=true` describes
capture reaching EOF, not whether a particular paginated response includes all
retained bytes. Offsets apply independently to both byte streams.

Completed metadata/output are retained up to 100 jobs / seven days, pruned on
the next job launch; at most 32 running jobs are admitted. No process output is
added to the central Activity database. Activity remains content-free and bounded
to its existing 10,000 entries / 30 days.

## Resource limits and remaining boundary

An owner may create private `job-resources.json` beside Agent state with
`{"memory_max_bytes": 268435456}` (example 256 MiB, not a production default).
It caps each newly launched systemd job and disables that job's swap. A malformed
or unprotected policy fails closed. Requests cannot choose a cgroup memory limit.
It is an OS-user policy, not an immutable security boundary against that same
user's filesystem access.

No universal memory cap is silently imposed on existing research. Cgroup RAM
limits and OOM preferences do not guarantee accounting of NVIDIA driver/unified
allocations or survival of global OOM. Independently protecting/restarting the
root-owned user manager requires a separately approved administrator policy;
the normal installer does not install one. The reviewable
`install/user-manager-recovery.conf.example` sets only `Restart=on-failure` and
`RestartSec=5s` for the intended user's root-owned `user@UID.service`. It affects
all services of that user and must be a distinct administrator opt-in. It does
not resume workloads ended during parent cleanup. The disposable acceptance
separately tests the default failure and this optional policy, then removes the
test drop-in. The normal installer does not change parent recovery policy automatically.

## Small compatibility additions

Core tool names remain unchanged. Capable Agents add contextual health/PSI and
optional accelerator data to `system.metrics`, and host health at `process.start`.
GPU probing is bounded; process launch does not run a GPU query. No automatic
disk cleaning or unrelated workload termination occurs.

Process filters remain literal. New Linux filters narrow explicitly and older
Agents reject unsupported narrowing arguments rather than ignore them. Search
supports exact directory-name exclusions and a text size bound; existing defaults
remain. `.gitignore`/glob language is left to client-side repository tools.

Local `status` is friendly; scripts must select `status --json` to retain the
prior JSON fields. Connection status verifies process start identity and boot ID,
and labels the last local connection observation; the panel confirms server
reachability. `activity` follows the existing journal; `--last N` reads and exits,
`--errors` filters failure/recovery entries. Custom installs use `--service`.
