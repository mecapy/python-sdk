"""Tests for Package, Function and Job abstractions."""

from unittest.mock import Mock, patch

import pytest

from mecapy import MecaPyClient
from mecapy.auth import Auth
from mecapy.exceptions import ExecutionError, NotFoundError, ValidationError
from mecapy.packages import Function, Job, Package

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
    def test_load_by_name(self):
        client = make_client()
        packages_resp = mock_response(
            200,
            {
                "packages": [
                    {"id": "uuid-1", "name": "e25-030-1"},
                    {"id": "uuid-2", "name": "other-pkg"},
                ]
            },
        )
        with patch.object(client, "_make_request", return_value=packages_resp):
            pkg = client.load("e25-030-1")
        assert isinstance(pkg, Package)
        assert pkg._id == "uuid-1"
        assert pkg._name == "e25-030-1"

    def test_load_by_id(self):
        client = make_client()
        packages_resp = mock_response(
            200,
            {
                "packages": [
                    {"id": "uuid-1", "name": "e25-030-1"},
                ]
            },
        )
        with patch.object(client, "_make_request", return_value=packages_resp):
            pkg = client.load("uuid-1")
        assert pkg._id == "uuid-1"

    def test_load_not_found_raises(self):
        client = make_client()
        packages_resp = mock_response(
            200,
            {
                "packages": [
                    {"id": "uuid-1", "name": "other-pkg"},
                ]
            },
        )
        with patch.object(client, "_make_request", return_value=packages_resp):
            with pytest.raises(NotFoundError, match="unknown-pkg"):
                client.load("unknown-pkg")
