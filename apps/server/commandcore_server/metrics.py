from __future__ import annotations

import threading


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "commandcore_mcp_requests_total": 0,
            "commandcore_mcp_errors_total": 0,
            "commandcore_agent_connections_total": 0,
            "commandcore_jobs_total": 0,
            "commandcore_job_errors_total": 0,
        }

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def render(self, online_agents: int) -> str:
        with self._lock:
            lines = [
                f"# TYPE {name} counter\n{name} {value}"
                for name, value in sorted(self._counters.items())
            ]
        lines.append(
            "# TYPE commandcore_agents_online gauge\ncommandcore_agents_online %d"
            % online_agents
        )
        return "\n".join(lines) + "\n"
