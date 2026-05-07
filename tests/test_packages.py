"""Tests for Package, Function and Job abstractions."""

import base64
from unittest.mock import Mock, patch

import pytest

from mecapy import MecaPyClient
from mecapy.auth import Auth
from mecapy.exceptions import ExecutionError, ValidationError
from mecapy.packages import (
    Function,
    Job,
    Package,
    _decode_output_files,
    _split_file_inputs,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_client() -> MecaPyClient:
    return MecaPyClient(api_url="https://api.example.com", auth=Auth.Token("tok"), timeout=5.0)


def make_package(client: MecaPyClient | None = None) -> Package:
    return Package(package_id="pkg-uuid", name="e25-030-1", client=client or make_client())


def mock_response(status: int, data: dict) -> Mock:
    resp = Mock()
    resp.status_code = status
    resp.json.return_value = data
    resp.text = str(data)
    return resp


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestJob:
    def test_repr(self):
        job = Job(job_id="abc-123", client=make_client())
        assert "abc-123" in repr(job)

    def test_status_completed(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(client, "_make_request", return_value=mock_response(200, {"status": "completed"})):
            assert job.status == "completed"

    def test_status_running_on_409(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(client, "_make_request", side_effect=ValidationError("running", 409)):
            assert job.status == "running"

    def test_status_reraises_non_409(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(client, "_make_request", side_effect=ValidationError("bad", 422)):
            with pytest.raises(ValidationError):
                _ = job.status

    def test_result_completed_first_poll(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {
                    "status": "completed",
                    "result": {"value": 42.0},
                },
            ),
        ):
            assert job.result() == {"value": 42.0}

    def test_result_cached_after_first_call(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {
                    "status": "completed",
                    "result": {"value": 42.0},
                },
            ),
        ) as mock_req:
            job.result()
            job.result()
            assert mock_req.call_count == 1  # second call uses cache

    def test_result_polls_through_409(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        responses = [
            ValidationError("running", 409),
            ValidationError("running", 409),
            mock_response(200, {"status": "completed", "result": {"v": 1}}),
        ]
        with patch.object(client, "_make_request", side_effect=responses):
            with patch("mecapy.packages.time.sleep"):  # skip actual sleeps
                result = job.result(poll_interval=0)
        assert result == {"v": 1}

    def test_result_raises_execution_error_on_failure(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {
                    "status": "failed",
                    "error": "division by zero",
                },
            ),
        ):
            with pytest.raises(ExecutionError, match="division by zero"):
                job.result()

    def test_result_raises_timeout(self):
        client = make_client()
        job = Job(job_id="abc-123", client=client)
        with patch.object(client, "_make_request", side_effect=ValidationError("running", 409)):
            with patch("mecapy.packages.time.sleep"):
                with patch("mecapy.packages.time.monotonic", side_effect=[0.0, 0.0, 999.0]):
                    with pytest.raises(TimeoutError):
                        job.result(timeout=1.0, poll_interval=0)


# ---------------------------------------------------------------------------
# Function
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFunction:
    def test_repr(self):
        fn = Function(name="min_preload", package=make_package())
        assert "min_preload" in repr(fn)
        assert "e25-030-1" in repr(fn)

    def test_submit_returns_job(self):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="min_preload", package=pkg)
        with patch.object(client, "_make_request", return_value=mock_response(200, {"job_id": "job-xyz"})):
            job = fn.submit(bolt={"d": 12})
        assert isinstance(job, Job)
        assert job.job_id == "job-xyz"

    def test_submit_posts_to_correct_endpoint(self):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="min_preload", package=pkg)
        with patch.object(client, "_make_request", return_value=mock_response(200, {"job_id": "x"})) as mock_req:
            fn.submit(bolt={"d": 12})
        mock_req.assert_called_once_with(
            "POST",
            "/packages/pkg-uuid/functions/min_preload/execute",
            json={"payload": {"bolt": {"d": 12}}},
        )

    def test_call_blocks_and_returns_result(self):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="min_preload", package=pkg)

        execute_resp = mock_response(200, {"job_id": "job-xyz"})
        result_resp = mock_response(200, {"status": "completed", "result": {"value": 30000.0}})

        with patch.object(client, "_make_request", side_effect=[execute_resp, result_resp]):
            result = fn(bolt={"d": 12})
        assert result == {"value": 30000.0}


# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPackage:
    def test_repr(self):
        pkg = make_package()
        assert "e25-030-1" in repr(pkg)
        assert "pkg-uuid" in repr(pkg)

    def test_getattr_returns_function(self):
        pkg = make_package()
        fn = pkg.min_preload
        assert isinstance(fn, Function)
        assert fn._name == "min_preload"

    def test_getattr_private_raises_attribute_error(self):
        pkg = make_package()
        with pytest.raises(AttributeError):
            _ = pkg._nonexistent

    def test_function_references_correct_package(self):
        pkg = make_package()
        fn = pkg.some_function
        assert fn._package is pkg


# ---------------------------------------------------------------------------
# MecaPyClient.load
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestClientLoad:
    """The namespace-only contract for ``client.load`` is covered in
    ``tests/test_workflows.py::TestClientLoadNamespace``. This stub kept
    so ``test_packages.py::TestClientLoad`` doesn't disappear from the
    grep radar — see the namespace tests for behaviour.
    """

    pass


# ---------------------------------------------------------------------------
# File upload helper (FRO-runtime-02 / Phase 5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFileInputs:
    """Detection of File kwargs (Path-like) and partitioning into payload + file_inputs."""

    def test_split_keeps_scalars_in_payload(self):
        payload, files = _split_file_inputs({"x": 1, "y": "hello", "z": {"d": 12}})
        assert payload == {"x": 1, "y": "hello", "z": {"d": 12}}
        assert files == {}

    def test_split_routes_path_to_files(self, tmp_path):
        sample = tmp_path / "in.txt"
        sample.write_text("payload")
        payload, files = _split_file_inputs({"file": sample, "factor": 2.5})
        assert payload == {"factor": 2.5}
        assert files == {"file": sample}

    def test_split_does_not_promote_string_path(self, tmp_path):
        # Plain str values stay scalar — callers must wrap with Path() to opt into upload.
        # Avoids accidental uploads when the function happens to take a string parameter
        # named like a filename.
        sample = tmp_path / "in.txt"
        sample.write_text("payload")
        payload, files = _split_file_inputs({"name": str(sample)})
        assert payload == {"name": str(sample)}
        assert files == {}


@pytest.mark.unit
class TestFunctionUpload:
    """Function.submit auto-upload behavior for Path kwargs."""

    def test_submit_uploads_then_executes(self, tmp_path):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="file_info", package=pkg)
        sample = tmp_path / "sample.txt"
        sample.write_text("hello\nworld\n")

        upload_resp = mock_response(201, {"upload_id": "upload-abc"})
        execute_resp = mock_response(200, {"job_id": "job-xyz"})

        with patch.object(client, "_make_request", side_effect=[upload_resp, execute_resp]) as mock_req:
            job = fn.submit(file=sample)

        assert isinstance(job, Job)
        assert job.job_id == "job-xyz"
        assert mock_req.call_count == 2

        # First call: multipart upload to the dedicated endpoint
        upload_call = mock_req.call_args_list[0]
        assert upload_call.args == ("POST", "/packages/pkg-uuid/functions/file_info/uploads")
        assert upload_call.kwargs["data"] == {"var_name": "file"}
        assert "files" in upload_call.kwargs
        upload_file_tuple = upload_call.kwargs["files"]["file"]
        assert upload_file_tuple[0] == "sample.txt"
        assert upload_file_tuple[1] == b"hello\nworld\n"

        # Second call: execute with file_inputs map (no payload entries from kwargs)
        execute_call = mock_req.call_args_list[1]
        assert execute_call.args == ("POST", "/packages/pkg-uuid/functions/file_info/execute")
        assert execute_call.kwargs["json"] == {
            "payload": {},
            "file_inputs": {"file": "upload-abc"},
        }

    def test_submit_partitions_files_and_scalars(self, tmp_path):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="hybrid", package=pkg)
        sample = tmp_path / "input.json"
        sample.write_text("{}")

        upload_resp = mock_response(201, {"upload_id": "upl-1"})
        execute_resp = mock_response(200, {"job_id": "job-1"})

        with patch.object(client, "_make_request", side_effect=[upload_resp, execute_resp]) as mock_req:
            fn.submit(file=sample, factor=2.5, mode="strict")

        # Single upload, then execute with both file_inputs and scalar payload
        execute_body = mock_req.call_args_list[1].kwargs["json"]
        assert execute_body == {
            "payload": {"factor": 2.5, "mode": "strict"},
            "file_inputs": {"file": "upl-1"},
        }

    def test_submit_multiple_file_inputs(self, tmp_path):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="merge", package=pkg)
        a = tmp_path / "a.txt"
        a.write_text("a")
        b = tmp_path / "b.txt"
        b.write_text("b")

        responses = [
            mock_response(201, {"upload_id": "id-a"}),
            mock_response(201, {"upload_id": "id-b"}),
            mock_response(200, {"job_id": "job-merge"}),
        ]
        with patch.object(client, "_make_request", side_effect=responses) as mock_req:
            fn.submit(left=a, right=b)

        assert mock_req.call_count == 3
        execute_body = mock_req.call_args_list[2].kwargs["json"]
        assert execute_body["file_inputs"] == {"left": "id-a", "right": "id-b"}

    def test_submit_omits_file_inputs_when_no_path(self):
        # Backward compat: scalar-only submits shouldn't add an empty file_inputs key
        # (existing API consumers expect plain `{"payload": {...}}`).
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="scale", package=pkg)
        with patch.object(client, "_make_request", return_value=mock_response(200, {"job_id": "j"})) as mock_req:
            fn.submit(force=100, factor=2)
        body = mock_req.call_args.kwargs["json"]
        assert body == {"payload": {"force": 100, "factor": 2}}
        assert "file_inputs" not in body

    def test_upload_raises_when_file_missing(self, tmp_path):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="file_info", package=pkg)
        with pytest.raises(ValidationError, match="not found"):
            fn.submit(file=tmp_path / "missing.txt")

    def test_upload_raises_when_path_is_directory(self, tmp_path):
        client = make_client()
        pkg = make_package(client)
        fn = Function(name="file_info", package=pkg)
        with pytest.raises(ValidationError, match="Not a regular file"):
            fn.submit(file=tmp_path)


# ---------------------------------------------------------------------------
# Output File decoding (FRO-runtime-02)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOutputFileDecoding:
    """`_output_files` arrives base64-encoded; SDK decodes transparently."""

    def test_decode_no_output_files_passthrough(self):
        result = {"value": 42, "other": "x"}
        assert _decode_output_files(result) is result  # original returned unchanged

    def test_decode_decodes_base64_entries(self):
        encoded = base64.b64encode(b"binary-payload").decode("ascii")
        decoded = _decode_output_files({"_output_files": {"chart": encoded}})
        assert decoded["_output_files"] == {"chart": b"binary-payload"}

    def test_decode_passes_through_bytes(self):
        # Defensive: if the API ever ships raw bytes, don't re-decode.
        decoded = _decode_output_files({"_output_files": {"chart": b"raw"}})
        assert decoded["_output_files"]["chart"] == b"raw"

    def test_decode_rejects_unexpected_type(self):
        with pytest.raises(ExecutionError, match="Unexpected"):
            _decode_output_files({"_output_files": {"chart": 123}})

    def test_job_result_decodes_output_files(self):
        encoded = base64.b64encode(b"PNG-bytes").decode("ascii")
        client = make_client()
        job = Job(job_id="abc", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {
                    "status": "completed",
                    "result": {"meta": "ok", "_output_files": {"render": encoded}},
                },
            ),
        ):
            result = job.result()
        assert result["meta"] == "ok"
        assert result["_output_files"] == {"render": b"PNG-bytes"}

    def test_download_outputs_writes_files(self, tmp_path):
        encoded = base64.b64encode(b"hello").decode("ascii")
        client = make_client()
        job = Job(job_id="abc", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {
                    "status": "completed",
                    "result": {"_output_files": {"hello.txt": encoded}},
                },
            ),
        ):
            written = job.download_outputs(tmp_path / "out")

        assert written == {"hello.txt": tmp_path / "out" / "hello.txt"}
        assert (tmp_path / "out" / "hello.txt").read_bytes() == b"hello"

    def test_download_outputs_returns_empty_when_no_files(self, tmp_path):
        client = make_client()
        job = Job(job_id="abc", client=client)
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(
                200,
                {"status": "completed", "result": {"value": 1}},
            ),
        ):
            written = job.download_outputs(tmp_path / "out")
        assert written == {}
        # Directory is intentionally not created when there are no files to write.
        assert not (tmp_path / "out").exists()
