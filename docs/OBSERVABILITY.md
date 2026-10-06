# Observability

**IMPLEMENTED:**

- `/healthz`
- authenticated `/metrics` Prometheus text endpoint
- Agent online/offline/last-seen state
- request and execution IDs
- persistent audit table
- MCP request/error counters
- Agent connection counter
- job/error counters

No heavy observability stack is bundled. Integrate these endpoints/log streams with whatever the deployment already uses.
