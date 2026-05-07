"""Workflow abstractions for the MecaPy SDK (FRO-namespace, session 53).

A workflow on MecaPy is a directed graph of FunctionVersion / InputNode /
ConstantNode that can be submitted as a single run from the SDK. From
the caller's point of view, a :class:`Workflow` behaves like a
single-callable artefact:

    >>> wf = client.load("acme/panneau-pub")  # latest
    >>> wf = client.load("acme/panneau-pub:0.3.0")  # pinned
    >>> handle = wf.submit(F=12.5, h=2.0)  # WorkflowRun handle
    >>> outputs = handle.result(timeout=60)  # blocks until completion
    >>> # — or —
    >>> outputs = wf(F=12.5, h=2.0)  # blocking sugar

Inputs are keyed by the workflow's InputNode ``node_key``s (the
workflow author chose those when wiring the graph). The handle exposes
the same ``status`` / ``result`` / ``download_outputs`` ergonomics as
:class:`mecapy.packages.Job`, adapted for a multi-step run.

Today, advancing a run requires the caller to drive the tick loop
explicitly via ``POST /workflow-runs/{id}/tick``. The :class:`WorkflowRun`
class encapsulates that loop with a polling cadence — same UX as Job's
``result(timeout=...)``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from .exceptions import ExecutionError

if TYPE_CHECKING:
    from .client import MecaPyClient


_DEFAULT_TICK_INTERVAL = 1.0
_DEFAULT_TIMEOUT = 600.0  # 10 min — workflows can chain multiple jobs.

_TERMINAL = ("completed", "failed", "cancelled", "timeout")


class WorkflowRun:
    """Handle on a single workflow run, mirroring :class:`mecapy.packages.Job`.

    The run is **not** advanced by the platform automatically (today) —
    the SDK explicitly ticks it via ``POST /workflow-runs/{id}/tick`` in
    the polling loop of :meth:`result`. Each tick may submit downstream
    function jobs; the run is "completed" once every terminal node has
    succeeded.
    """

    def __init__(self, run_id: str, workflow_slug: str, client: MecaPyClient) -> None:
        self.run_id = run_id
        self._slug = workflow_slug
        self._client = client
        self._last_status: dict[str, Any] | None = None

    @property
    def status(self) -> str:
        """Latest known status string (``pending``/``running``/``completed`` …).

        Re-fetched lazily on access; callers polling tightly should
        prefer :meth:`refresh` to avoid double round-trips.
        """
        return self.refresh()["status"]

    def refresh(self) -> dict[str, Any]:
        """Re-fetch the run state from the API and cache it."""
        resp = self._client._make_request("GET", f"/workflow-runs/{self.run_id}")
        self._last_status = resp.json()
        return self._last_status

    def tick(self) -> dict[str, Any]:
        """Manually drive the orchestration loop one step forward.

        Returns the post-tick run state. Most users won't need this —
        :meth:`result` ticks for them. Useful for tests and CLI debugging.
        """
        resp = self._client._make_request("POST", f"/workflow-runs/{self.run_id}/tick")
        self._last_status = resp.json()
        return self._last_status

    def result(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        poll_interval: float = _DEFAULT_TICK_INTERVAL,
    ) -> dict[str, Any]:
        """Block until the run reaches a terminal state and return its
        terminal_outputs (or raise :class:`ExecutionError` on failure).

        The SDK ticks the run after each ``poll_interval`` until the
        ``status`` becomes one of ``completed`` / ``failed`` /
        ``cancelled`` / ``timeout`` (or the local ``timeout`` elapses).
        """
        deadline = time.monotonic() + timeout
        while True:
            state = self.tick()
            status = state.get("status", "pending")
            if status in _TERMINAL:
                if status == "completed":
                    return state.get("terminal_outputs") or {}
                # Surface the first failed node + its message in the
                # raised exception so callers can locate the failure.
                msg = state.get("error_message") or status
                first_failed = state.get("first_failed_node_key")
                raise ExecutionError(
                    f"Workflow {self._slug!r} run {self.run_id!r} {status}: "
                    f"{msg}" + (f" (first failed: {first_failed})" if first_failed else "")
                )
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Workflow run {self.run_id!r} did not complete within {timeout}s (last status: {status})"
                )
            time.sleep(poll_interval)

    def __repr__(self) -> str:
        return f"WorkflowRun(run_id={self.run_id!r}, workflow={self._slug!r})"


class Workflow:
    """A deployed MecaPy workflow callable from the SDK.

    Obtained via :meth:`MecaPyClient.load` when the namespace path
    resolves to a workflow (kind = "workflow" in the registry response).
    Two calling styles, identical in spirit to :class:`mecapy.packages.Function`:

    * **Blocking** — ``wf(**inputs)`` submits the run, polls until
      completion, returns ``terminal_outputs``.
    * **Non-blocking** — ``wf.submit(**inputs)`` returns a
      :class:`WorkflowRun` handle; call ``.result(timeout=...)`` later.

    Inputs are keyed by the workflow's InputNode ``node_key``\\ s — the
    workflow author chose them at design time, so the SDK contract is
    "just pass the keyword arguments the workflow expects".

    Parameters
    ----------
    workflow_id : str
        UUID of the workflow.
    slug : str
        Human-readable slug (kept for repr / error messages — the
        request path itself uses ``slug`` until the API migrates to
        UUID-based routing in a future namespace pass).
    owner : str
        Owner's organisation slug or username (whatever the registry
        accepted at lookup time).
    version : str
        Resolved version string (semver).
    client : MecaPyClient
        Authenticated client used to call the API.
    """

    def __init__(
        self,
        workflow_id: str,
        slug: str,
        owner: str,
        version: str,
        client: MecaPyClient,
    ) -> None:
        self._id = workflow_id
        self._slug = slug
        self._owner = owner
        self._version = version
        self._client = client

    def submit(self, **inputs: Any) -> WorkflowRun:
        """Submit the workflow with the given inputs and return the handle.

        ``**inputs`` keys must match the workflow's InputNode
        ``node_key``\\ s — typically the same names the author wrote in
        the editor when creating each input node.
        """
        body = {"inputs": dict(inputs)}
        resp = self._client._make_request(
            "POST",
            f"/workflows/{self._id}/runs",
            json=body,
        )
        run_id = resp.json()["id"]
        return WorkflowRun(run_id=run_id, workflow_slug=self._slug, client=self._client)

    def __call__(self, **inputs: Any) -> dict[str, Any]:
        """Blocking submit + wait for terminal state — sugar for
        ``submit(**inputs).result()``.
        """
        run = self.submit(**inputs)
        return run.result()

    def __repr__(self) -> str:
        return f"Workflow(owner={self._owner!r}, slug={self._slug!r}, version={self._version!r})"
