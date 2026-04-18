"""Package, Function and Job abstractions for the MecaPy SDK."""

import time
from typing import TYPE_CHECKING, Any

from .exceptions import ExecutionError, ValidationError

if TYPE_CHECKING:
    from .client import MecaPyClient

_DEFAULT_TIMEOUT = 120.0
_DEFAULT_POLL_INTERVAL = 2.0


class Job:
    """Represents an asynchronous computation job submitted to MecaPy.

    Returned by :meth:`Function.submit`. Call :meth:`result` to retrieve the
    output (blocking).

    Parameters
    ----------
    job_id : str
        Unique job identifier returned by the API.
    client : MecaPyClient
        Client used to poll the result endpoint.

    Examples
    --------
    >>> job = pkg.min_preload.submit(bolt=..., assembly=..., loads=..., tightening=...)
    >>> print(job.status)  # non-blocking
    >>> result = job.result()  # blocks until done
    """

    def __init__(self, job_id: str, client: "MecaPyClient") -> None:
        self.job_id = job_id
        self._client = client
        self._cached_result: dict[str, Any] | None = None

    @property
    def status(self) -> str:
        """Current job status without blocking.

        Returns
        -------
        str
            One of ``"pending"``, ``"running"``, ``"completed"``, ``"failed"``.
        """
        try:
            resp = self._client._make_request("GET", f"/jobs/{self.job_id}/result")
            return str(resp.json().get("status", "unknown"))
        except ValidationError as exc:
            if exc.status_code == 409:
                return "running"
            raise

    def result(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Block until the job completes and return the result dict.

        Parameters
        ----------
        timeout : float
            Maximum seconds to wait before raising :class:`TimeoutError`.
        poll_interval : float
            Seconds between polling attempts.

        Returns
        -------
        dict[str, Any]
            Output of the remote function.

        Raises
        ------
        ExecutionError
            If the job failed on the server side.
        TimeoutError
            If the job did not complete within *timeout* seconds.
        """
        if self._cached_result is not None:
            return self._cached_result

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            output = self._poll_once()
            if output is not None:
                self._cached_result = output
                return self._cached_result
            time.sleep(poll_interval)

        raise TimeoutError(f"Job {self.job_id} did not complete within {timeout}s")

    def _poll_once(self) -> dict[str, Any] | None:
        """Single poll attempt.

        Returns
        -------
        dict[str, Any] | None
            Result dict when completed, ``None`` when still running.

        Raises
        ------
        ExecutionError
            If the job failed on the server side.
        ValidationError
            For unexpected API errors (not 409).
        """
        try:
            resp = self._client._make_request("GET", f"/jobs/{self.job_id}/result")
            data = resp.json()
        except ValidationError as exc:
            if exc.status_code == 409:
                return None
            raise

        status = data.get("status")
        if status == "completed":
            return data.get("result", {})
        if status == "failed":
            raise ExecutionError(f"Job {self.job_id} failed: {data.get('error', 'unknown error')}")
        return None

    def __repr__(self) -> str:
        return f"Job(job_id={self.job_id!r})"


class Function:
    """A callable remote function exposed by a MecaPy package.

    Obtained via attribute access on a :class:`Package` object.
    Supports two calling styles:

    - **Blocking** — ``pkg.fn(**kwargs)`` submits the job and waits for the result.
    - **Non-blocking** — ``pkg.fn.submit(**kwargs)`` returns a :class:`Job` immediately.

    Parameters
    ----------
    name : str
        Function name as registered in the package manifest.
    package : Package
        Parent package that owns this function.

    Examples
    --------
    >>> result = pkg.min_preload(bolt=..., assembly=..., loads=..., tightening=...)
    >>> job = pkg.min_preload.submit(bolt=..., assembly=..., loads=..., tightening=...)
    >>> result = job.result()
    """

    def __init__(self, name: str, package: "Package") -> None:
        self._name = name
        self._package = package

    def submit(self, **kwargs: Any) -> Job:
        """Submit the job without blocking.

        Parameters
        ----------
        **kwargs
            Keyword arguments forwarded to the remote function as payload.

        Returns
        -------
        Job
            Job handle; call :meth:`Job.result` to retrieve the output.
        """
        resp = self._package._client._make_request(
            "POST",
            f"/packages/{self._package._id}/functions/{self._name}/execute",
            json={"payload": kwargs},
        )
        job_id = resp.json()["job_id"]
        return Job(job_id=job_id, client=self._package._client)

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        """Submit and block until the result is ready.

        Parameters
        ----------
        **kwargs
            Keyword arguments forwarded to the remote function as payload.

        Returns
        -------
        dict[str, Any]
            Output of the remote function.
        """
        return self.submit(**kwargs).result()

    def __repr__(self) -> str:
        return f"Function(name={self._name!r}, package={self._package._name!r})"


class Package:
    """A deployed MecaPy package whose functions are accessible as attributes.

    Obtained via :meth:`MecaPyClient.load`.

    Parameters
    ----------
    package_id : str
        UUID of the package in the MecaPy platform.
    name : str
        Human-readable package name (e.g. ``"e25-030-1"``).
    client : MecaPyClient
        Authenticated client used to call the API.

    Examples
    --------
    >>> pkg = client.load("e25-030-1")
    >>> result = pkg.min_preload(bolt=..., assembly=..., loads=..., tightening=...)
    """

    def __init__(self, package_id: str, name: str, client: "MecaPyClient") -> None:
        self._id = package_id
        self._name = name
        self._client = client

    def __getattr__(self, name: str) -> Function:
        if name.startswith("_"):
            raise AttributeError(name)
        return Function(name=name, package=self)

    def __repr__(self) -> str:
        return f"Package(name={self._name!r}, id={self._id!r})"
