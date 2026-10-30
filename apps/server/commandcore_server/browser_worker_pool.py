"""Explicitly provisioned one-owner-per-worker Browser dispatcher.

No dynamic container creation. Each worker points to a distinct private Steel
instance and has an immutable operator-preassigned OAuth owner binding.
The worker/host identity must be checked by the deployment orchestrator; URL
uniqueness is necessary but not proof of separate physical worker processes.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

from .browser_gateway import BrowserError, BrowserGateway
from .browser_worker_attestation import (
    BrowserAttestationError,
    WorkerAttestationVerifier,
)
from .browser_worker_attestation_ed25519 import Ed25519WorkerAttestationVerifier
from .browser_worker_binding import BrowserWorkerBinding, WorkerOwnershipError

ProofVerifier = WorkerAttestationVerifier | Ed25519WorkerAttestationVerifier
from urllib.parse import urlsplit

Owner = tuple[str, str, str]


class OwnerBrowserWorkerPool:
    def __init__(
        self,
        workers: list[BrowserGateway],
        attestation: ProofVerifier | None = None,
    ):
        if not workers or len(workers) > 16:
            raise ValueError("browser worker pool must have 1-16 provisioned workers")
        seen_ids: set[str] = set()
        seen_backend: set[str] = set()
        seen_bindings: set[str] = set()
        for worker in workers:
            binding = worker.worker_binding
            if binding is None:
                raise ValueError(
                    "each browser worker must have a persistent owner binding"
                )
            if binding.worker_id in seen_ids or worker.base_url in seen_backend:
                raise ValueError("duplicate browser worker ID or Steel endpoint")
            if str(binding.path) in seen_bindings:
                raise ValueError("one binding cannot control multiple Steel workers")
            seen_ids.add(binding.worker_id)
            seen_backend.add(worker.base_url)
            seen_bindings.add(str(binding.path))
        self.workers = tuple(workers)
        self.public_base_url = workers[0].public_base_url
        self.attestation = attestation
        self._worker_starts: dict[str, str] = {}
        if self.attestation is not None:
            for gateway in self.workers:
                binding = gateway.worker_binding
                assert binding is not None
                try:
                    stamp = self.attestation.verify(binding.worker_id).get(
                        "steel_started_at", ""
                    )
                except BrowserAttestationError:
                    continue  # Fail closed until the operator publishes fresh proof.
                if stamp:
                    self._worker_starts[binding.worker_id] = stamp

    @classmethod
    def from_manifest(
        cls,
        path: str,
        binding_secret: str,
        allow_hosts: tuple[str, ...],
        public_base_url: str,
        attestation: ProofVerifier | None = None,
    ) -> OwnerBrowserWorkerPool:
        source = Path(path)
        try:
            parent = source.parent.stat()
            st = source.lstat()
            if (
                not source.is_absolute()
                or not stat.S_ISREG(st.st_mode)
                or st.st_mode & 0o077
                or parent.st_mode & 0o022
            ):
                raise ValueError("browser worker manifest requires private permissions")
            body = json.loads(source.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("browser worker manifest unavailable") from exc
        if not isinstance(body, dict) or not isinstance(body.get("workers"), list):
            raise ValueError("browser worker manifest requires workers list")  # noqa: TRY004 - invalid external data
        workers = []
        for row in body["workers"]:
            if (
                not isinstance(row, dict)
                or set(row)
                != {
                    "worker_id",
                    "binding_path",
                    "steel_url",
                    "cdp_url",
                    "egress_proxy_url",
                    "egress_policy_url",
                }
                or any(not isinstance(v, str) or not v.strip() for v in row.values())
            ):
                raise ValueError("malformed browser worker specification")
            binding = BrowserWorkerBinding(
                row["binding_path"],
                row["worker_id"],
                binding_secret,
                require_claimed=True,
            )
            workers.append(
                BrowserGateway(
                    base_url=row["steel_url"],
                    cdp_url=row["cdp_url"],
                    egress_proxy_url=row["egress_proxy_url"],
                    egress_policy_url=row["egress_policy_url"],
                    allow_hosts=allow_hosts,
                    public_base_url=public_base_url,
                    worker_binding=binding,
                )
            )
        return cls(workers, attestation=attestation)

    def _verify_physical_assignment(self, worker: BrowserGateway) -> None:
        if self.attestation is None:
            return
        binding = worker.worker_binding
        assert binding is not None
        try:
            row = self.attestation.verify(binding.worker_id)
        except BrowserAttestationError as exc:
            # A proof outage is a trust loss, not merely an availability
            # warning. Scrub the cached frames and human handoff tokens even
            # when the signer later returns with the same worker incarnation.
            # Pending actions must still fail the postflight proof check.
            worker.sessions.clear()
            raise BrowserError(
                "browser physical worker not currently verified"
            ) from exc
        start_stamp = row.get("steel_started_at", "")
        if not start_stamp:
            raise BrowserError("browser worker runtime incarnation is unverified")
        old_stamp = self._worker_starts.get(binding.worker_id)
        if old_stamp is None and worker.sessions:
            # A session cannot predate our first verified physical incarnation.
            worker.sessions.clear()
            self._worker_starts[binding.worker_id] = start_stamp
            raise BrowserError("unverified previous browser session invalidated")
        if old_stamp is not None and old_stamp != start_stamp:
            # A reused container ID is not a reused Chromium process/profile.
            # Invalidate all sessions and embedded handoff tokens immediately.
            worker.sessions.clear()
            self._worker_starts[binding.worker_id] = start_stamp
            raise BrowserError("browser worker restarted; old session invalidated")
        self._worker_starts[binding.worker_id] = start_stamp
        # The operator's physical snapshot pins the approved boundary container.
        # The application's control/CDP endpoint cannot be silently redirected
        # to a different worker or directly to an unisolated Steel API.
        approved_hosts = {
            row["boundary_name"],
            "ccctl-" + binding.worker_id,
        }
        base = urlsplit(worker.base_url)
        cdp = urlsplit(worker.cdp_url)
        policy = urlsplit(worker.egress_policy_url)
        proxy = urlsplit(worker.egress_proxy_url)
        if (
            policy.hostname != base.hostname
            or policy.port != 8080
            or proxy.hostname != "browser-boundary"
            or proxy.port != 8080
        ):
            raise BrowserError("browser proxy policy endpoints are not isolated")
        if (
            base.hostname not in approved_hosts
            or cdp.hostname != base.hostname
            or base.port != 3000
            or cdp.port != 3000
        ):
            raise BrowserError(
                "browser worker control endpoint is not physically attested"
            )

    def _find_worker(self, owner: Owner) -> BrowserGateway:
        found: BrowserGateway | None = None
        for worker in self.workers:
            binding = worker.worker_binding
            assert binding is not None
            try:
                if binding.matches(owner):
                    if found is not None:
                        raise BrowserError("ambiguous browser worker assignment")
                    found = worker
            except WorkerOwnershipError as exc:
                raise BrowserError("browser worker binding unavailable") from exc
        if found is None:
            raise BrowserError("no provisioned browser worker for OAuth owner")
        self._verify_physical_assignment(found)
        return found

    def available(self, issuer: str, subject: str, client_id: str) -> bool:
        """Display only currently owner-bound AND physically attested workers."""
        try:
            self._find_worker((issuer, subject, client_id))
        except (BrowserError, WorkerOwnershipError):
            return False
        return True

    async def call(
        self,
        *,
        subject: str,
        issuer: str,
        client_id: str,
        name: str,
        args: dict[str, Any],
        human: bool = False,
        human_token: str | None = None,
    ) -> dict[str, Any]:
        owner = (issuer, subject, client_id)
        worker = self._find_worker(owner)
        result = await worker.call(
            subject=subject,
            issuer=issuer,
            client_id=client_id,
            name=name,
            args=args,
            human=human,
            human_token=human_token,
        )
        # The operator's physical proof can expire or the Chromium process can
        # be replaced while a CDP action awaits network/renderer responses.
        # Never expose a screenshot/action success from an incarnation that is
        # no longer physically attested. A changed incarnation also invalidates
        # the in-memory sessions and their human handoff tokens.
        self._verify_physical_assignment(worker)
        return result

    def viewer_sessions(self, subject: str, issuer: str) -> list[dict[str, str]]:
        """Owner-only discovery; a panel never supplies another subject/issuer."""
        rows = []
        for worker in self.workers:
            for owner, entry in list(worker.sessions.items()):
                if owner[0] == issuer and owner[1] == subject:
                    if self._find_worker(owner) is not worker:
                        raise BrowserError("browser owner binding changed")
                    rows.append({"client_id": owner[2], "session_id": entry.id})
        return rows

    async def viewer_frame(
        self, subject: str, issuer: str, client_id: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        worker = self._find_worker((issuer, subject, client_id))
        result = await worker.viewer_frame(subject, issuer, client_id, args)
        self._verify_physical_assignment(worker)
        return result

    def handoff_owner(self, token: str, subject: str, issuer: str = "") -> Owner:
        found: Owner | None = None
        for worker in self.workers:
            try:
                owner = worker.handoff_owner(token, subject, issuer)
            except BrowserError:
                continue
            if found is not None:
                raise BrowserError("ambiguous browser handoff owner")
            # A valid handoff is not enough if the persistent binding changed.
            if self._find_worker(owner) is not worker:
                raise BrowserError("browser owner binding changed")
            found = owner
        if found is None:
            raise BrowserError("browser handoff not found")
        return found

    async def human_call(
        self,
        token: str,
        subject: str,
        name: str,
        args: dict[str, Any],
        issuer: str = "",
    ) -> dict[str, Any]:
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await worker.human_call(
            token,
            subject,
            name,
            args,
            issuer=issuer,
        )
        self._verify_physical_assignment(worker)
        return result

    async def private_stream_frame(
        self, token: str, subject: str, issuer: str = ""
    ) -> dict[str, Any]:
        """Resolve an attested, owner-bound worker for every private frame."""
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await worker.private_stream_frame(token, subject, issuer)
        self._verify_physical_assignment(worker)
        return result

    async def human_resume(
        self,
        token: str,
        subject: str,
        issuer: str = "",
        *,
        allow_ai_interaction: bool = False,
    ) -> dict[str, Any]:
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await worker.human_resume(
            token,
            subject,
            issuer,
            allow_ai_interaction=allow_ai_interaction,
        )
        self._verify_physical_assignment(worker)
        return result
