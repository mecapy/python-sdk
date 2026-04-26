"""Package, Function and Job abstractions for the MecaPy SDK."""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .exceptions import ExecutionError, ValidationError

if TYPE_CHECKING:
    from .client import MecaPyClient

_DEFAULT_TIMEOUT = 120.0
_DEFAULT_POLL_INTERVAL = 2.0

# Result dict key used by the API to surface base64-encoded output Files
# (see docker_executor.py / FRO-runtime-02). The SDK decodes this key to
# raw bytes before handing the result to the user.
_OUTPUT_FILES_KEY = "_output_files"


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

    def __init__(self, job_id: str, client: MecaPyClient) -> None:
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

        Output Files (FRO-runtime-02) are surfaced under the
        ``_output_files`` key as ``{var_name: bytes}``. They arrive
        base64-encoded over the wire and are decoded transparently here so
        callers can treat them as raw bytes (or write them to disk via
        :meth:`download_outputs`).

        Parameters
        ----------
        timeout : float
            Maximum seconds to wait before raising :class:`TimeoutError`.
        poll_interval : float
            Seconds between polling attempts.

        Returns
        -------
        dict[str, Any]
            Output of the remote function, with ``_output_files`` (if
            present) decoded to ``{var: bytes}``.

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
                self._cached_result = _decode_output_files(output)
                return self._cached_result
            time.sleep(poll_interval)

        raise TimeoutError(f"Job {self.job_id} did not complete within {timeout}s")

    def download_outputs(self, directory: str | Path) -> dict[str, Path]:
        r"""Write each output File from ``_output_files`` to disk.

        Convenience helper for the common case where the caller wants the
        raw bytes persisted as files. The result dict keeps its decoded
        bytes alongside; this method only adds disk-side copies.

        Parameters
        ----------
        directory : str | Path
            Target directory. Created (with parents) if missing.

        Returns
        -------
        dict[str, Path]
            Mapping ``{var_name: written_path}``. Empty if the result has
            no ``_output_files``.

        Examples
        --------
        >>> job = pkg.render.submit(input=Path("scene.json"))
        >>> job.result()
        {'_output_files': {'rendered': b'\x89PNG...'}}
        >>> job.download_outputs("./out")
        {'rendered': PosixPath('out/rendered')}
        """
        result = self.result()
        files = result.get(_OUTPUT_FILES_KEY, {})
        if not files:
            return {}

        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)

        written: dict[str, Path] = {}
        for var_name, content in files.items():
            path = target / var_name
            path.write_bytes(content if isinstance(content, bytes) else bytes(content))
            written[var_name] = path
        return written

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

    File inputs (per FRO-runtime-02) are detected automatically: any kwarg
    whose value is a :class:`pathlib.Path` is uploaded out-of-band via
    ``POST /packages/{id}/functions/{name}/uploads`` and the resulting
    ``upload_id`` is forwarded under ``file_inputs`` in the execute request.
    All other kwargs travel inline in ``payload``.

    Parameters
    ----------
    name : str
        Function name as registered in the package manifest.
    package : Package
        Parent package that owns this function.

    Examples
    --------
    Scalar inputs (E25-030-1 style)::

        result = pkg.min_preload(bolt=..., assembly=..., loads=..., tightening=...)
        job = pkg.min_preload.submit(bolt=..., assembly=..., loads=..., tightening=...)

    File input (Path-like is auto-uploaded)::

        from pathlib import Path

        result = pkg.file_info(file=Path("./sample.txt"))
        # → {'size_bytes': 111, 'sha256': '...', 'line_count': 3}
    """

    def __init__(self, name: str, package: Package) -> None:
        self._name = name
        self._package = package

    def submit(self, **kwargs: Any) -> Job:
        """Submit the job without blocking.

        Walks ``kwargs`` and partitions File inputs (Path-like values) from
        scalar inputs. Each File is uploaded first; its ``upload_id`` is
        then referenced in the execute request's ``file_inputs`` map.

        Parameters
        ----------
        **kwargs
            Keyword arguments forwarded to the remote function. Values of
            type :class:`pathlib.Path` are uploaded via the dedicated
            ``/uploads`` endpoint and referenced by ``upload_id``; all
            other values are sent inline as ``payload``.

        Returns
        -------
        Job
            Job handle; call :meth:`Job.result` to retrieve the output.
        """
        payload, file_kwargs = _split_file_inputs(kwargs)

        file_inputs: dict[str, str] = {}
        for var_name, file_path in file_kwargs.items():
            file_inputs[var_name] = self._upload_file(var_name, file_path)

        body: dict[str, Any] = {"payload": payload}
        if file_inputs:
            body["file_inputs"] = file_inputs

        resp = self._package._client._make_request(
            "POST",
            f"/packages/{self._package._id}/functions/{self._name}/execute",
            json=body,
        )
        job_id = resp.json()["job_id"]
        return Job(job_id=job_id, client=self._package._client)

    def _upload_file(self, var_name: str, file_path: Path) -> str:
        """Upload a File input and return its ``upload_id``.

        POSTs the file to
        ``/packages/{pkg_id}/functions/{fn}/uploads`` (multipart). The API
        validates the var_name against the function's typed io_spec and the
        extension against the ``File[ext1,ext2,...]`` constraint.

        Raises
        ------
        ValidationError
            If the file does not exist locally, or the API rejects the
            var_name / extension (HTTP 422).
        """
        if not file_path.exists():
            raise ValidationError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise ValidationError(f"Not a regular file: {file_path}")

        with file_path.open("rb") as fh:
            files = {"file": (file_path.name, fh.read())}
            data = {"var_name": var_name}
            resp = self._package._client._make_request(
                "POST",
                f"/packages/{self._package._id}/functions/{self._name}/uploads",
                files=files,
                data=data,
            )
        return str(resp.json()["upload_id"])

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        """Submit and block until the result is ready.

        Parameters
        ----------
        **kwargs
            Keyword arguments forwarded to the remote function as payload.
            File inputs (:class:`pathlib.Path` values) are auto-uploaded;
            see :meth:`submit`.

        Returns
        -------
        dict[str, Any]
            Output of the remote function. Output Files (if any) are
            decoded under ``_output_files`` as ``{var_name: bytes}``.
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

    def __init__(self, package_id: str, name: str, client: MecaPyClient) -> None:
        self._id = package_id
        self._name = name
        self._client = client

    def __getattr__(self, name: str) -> Function:
        if name.startswith("_"):
            raise AttributeError(name)
        return Function(name=name, package=self)

    def __repr__(self) -> str:
        return f"Package(name={self._name!r}, id={self._id!r})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_file_inputs(
    kwargs: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Path]]:
    """Partition ``kwargs`` into (scalar payload, File inputs).

    A kwarg is treated as a File input when its value is a
    :class:`pathlib.Path`. Plain strings are kept as scalar values to avoid
    accidental uploads — callers must wrap with ``Path(...)`` to opt in.
    """
    payload: dict[str, Any] = {}
    files: dict[str, Path] = {}
    for var_name, value in kwargs.items():
        if isinstance(value, Path):
            files[var_name] = value
        else:
            payload[var_name] = value
    return payload, files


def _decode_output_files(result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``result`` with ``_output_files`` decoded to bytes.

    The API serialises File outputs as base64 strings (per Phase 5). The
    SDK transparently decodes them so handlers can be consumed as raw
    bytes without callers worrying about the wire format.

    Returns the original dict unchanged when no ``_output_files`` key is
    present (dominant case for scalar-only handlers).
    """
    files = result.get(_OUTPUT_FILES_KEY)
    if not isinstance(files, dict) or not files:
        return result

    decoded: dict[str, bytes] = {}
    for var_name, encoded in files.items():
        if isinstance(encoded, bytes):
            decoded[var_name] = encoded
            continue
        if not isinstance(encoded, str):
            raise ExecutionError(
                f"Unexpected {_OUTPUT_FILES_KEY!r} entry for {var_name!r}: "
                f"expected str or bytes, got {type(encoded).__name__}"
            )
        decoded[var_name] = base64.b64decode(encoded)

    out = dict(result)
    out[_OUTPUT_FILES_KEY] = decoded
    return out
