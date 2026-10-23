# Browser security review

This records a source review and negative regression coverage. It is not an
independent penetration-test certification. Platform and deployment acceptance
remain required before broad public availability.

| Boundary | Enforcement and regression evidence |
|---|---|
| Account and conversation | OAuth issuer, subject, client, verified host conversation and scoped ephemeral viewer; foreign task/viewer requests denied |
| Restart identity | Private durable HMAC key binds task tags; viewer capabilities stay ephemeral; legacy lost tags never rebound by task ID |
| Private control | Authenticated owner handoff/resume; immediately withhold screenshots and AI actions; expiry/restart preserves pause |
| Website effects | Search uses encoded public query; link references revalidate visible page, label and target; consequential controls denied before dispatch; history uses GET |
| Network | HTTPS:443 public DNS policy; deny credentials/IP literals/private names; reject complete mixed public/private DNS answer sets and connect to validated numeric address |
| Worker isolation | Permanent owner binding, distinct endpoints and fresh signed physical worker proof; no MCP Docker access; operator validates topology |
| Display state | Persist only bounded task summary tied to this task ID; no viewer capability, screenshots, command text or file paths |
| Recovery/retry | Status refresh only; no automatic retry of timed-out writes or uncertain website actions; stale responses cannot overwrite a final state |
| Distribution | Private DB/key/journals excluded; console assets packaged; dependencies locked and audited; production configuration never copied into public source |

Review the proxy together with the actual Docker routing and sandbox policy:
initial-URL validation alone is not an egress firewall. Public mode deliberately
permits public web access; it is not an information-flow guarantee for secrets
submitted by an authorized user. Never give page text authority over tools.

The current source includes regression coverage for malicious URLs, mixed DNS,
stale/tampered/foreign worker proofs, private frame withholding, changed links,
conversation isolation, restart identity, and key-file type/mode/link checks.
The key reader uses nonblocking open so a substituted FIFO cannot hang startup.
Task-key validation depends on POSIX filesystem protection in the Linux server
deployment; native Windows server hosting is not a supported Browser target.

Residual release gates: independent security review of deployment topology,
full CI matrix on the candidate commit, and native platform lifecycle evidence
where that platform is advertised. Do not interpret passing unit tests as
proof that an arbitrary operator's worker network is isolated.
