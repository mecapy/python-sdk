"""Tests for the Workflow + WorkflowRun SDK abstractions and the
namespace-aware ``client.load`` (FRO-namespace, session 53).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from mecapy import MecaPyClient, Workflow, WorkflowRun
from mecapy.auth import Auth
from mecapy.exceptions import ExecutionError, NotFoundError
from mecapy.packages import Package


def make_client() -> MecaPyClient:
    return MecaPyClient(
        api_url="https://api.example.com",
        auth=Auth.Token("tok"),
        timeout=5.0,
    )


def mock_response(status: int, data: dict) -> Mock:
    resp = Mock()
    resp.status_code = status
    resp.json.return_value = data
    return resp


# --------------------------------------------------------------------------- #
# Workflow                                                                     #
# --------------------------------------------------------------------------- #


class TestWorkflowSubmit:
    def test_submit_returns_workflow_run_handle(self):
        client = make_client()
        wf = Workflow(
            workflow_id="wf-1",
            slug="panneau-pub",
            owner="acme",
            version="0.3.0",
            client=client,
        )
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(201, {"id": "run-xyz"}),
        ) as mock_req:
            run = wf.submit(F=12.5, h=2.0)

        assert isinstance(run, WorkflowRun)
        assert run.run_id == "run-xyz"
        # Verify the SDK posts to the workflow runs endpoint with the
        # right body shape.
        call_args = mock_req.call_args
        assert call_args.args[:2] == ("POST", "/workflows/wf-1/runs")
        assert call_args.kwargs["json"] == {"inputs": {"F": 12.5, "h": 2.0}}


class TestWorkflowRunResult:
    def test_completed_returns_terminal_outputs(self):
        client = make_client()
        run = WorkflowRun(run_id="run-1", workflow_slug="wf", client=client)
        ticks = [
            mock_response(200, {"status": "running"}),
            mock_response(
                200,
                {
                    "status": "completed",
                    "terminal_outputs": {"sigma": 145.2, "marge": 0.3},
                },
            ),
        ]
        with patch.object(client, "_make_request", side_effect=ticks):
            outputs = run.result(timeout=5.0, poll_interval=0.0)
        assert outputs == {"sigma": 145.2, "marge": 0.3}

    def test_failed_raises_execution_error_with_first_failed_node(self):
        client = make_client()
        run = WorkflowRun(run_id="run-1", workflow_slug="wf", client=client)
        ticks = [
            mock_response(
                200,
                {
                    "status": "failed",
                    "error_message": "div by zero",
                    "first_failed_node_key": "F1",
                },
            ),
        ]
        with patch.object(client, "_make_request", side_effect=ticks):
            with pytest.raises(ExecutionError, match="first failed: F1"):
                run.result(timeout=1.0, poll_interval=0.0)

    def test_timeout_raises_timeout_error(self):
        client = make_client()
        run = WorkflowRun(run_id="run-1", workflow_slug="wf", client=client)
        # Always running — never reaches terminal state.
        with patch.object(
            client,
            "_make_request",
            return_value=mock_response(200, {"status": "running"}),
        ):
            with pytest.raises(TimeoutError):
                run.result(timeout=0.0, poll_interval=0.0)


class TestWorkflowCallable:
    def test_call_is_sugar_for_submit_then_result(self):
        client = make_client()
        wf = Workflow(
            workflow_id="wf-1",
            slug="panneau-pub",
            owner="acme",
            version="0.3.0",
            client=client,
        )
        responses = [
            mock_response(201, {"id": "run-xyz"}),  # submit
            mock_response(
                200,
                {"status": "completed", "terminal_outputs": {"answer": 42}},
            ),  # tick
        ]
        with patch.object(client, "_make_request", side_effect=responses):
            outputs = wf(F=1.0, h=2.0)
        assert outputs == {"answer": 42}


# --------------------------------------------------------------------------- #
# client.load — namespace path resolution                                      #
# --------------------------------------------------------------------------- #


class TestClientLoadNamespace:
    def test_load_namespace_returns_workflow_when_registry_matches(self):
        client = make_client()
        registry_resp = mock_response(
            200,
            {
                "kind": "workflow",
                "owner": "acme",
                "slug": "panneau-pub",
                "version": "0.3.0",
                "workflow_id": "wf-uuid",
                "version_id": "ver-uuid",
            },
        )
        with patch.object(client, "_make_request", return_value=registry_resp) as mock_req:
            obj = client.load("acme/panneau-pub:0.3.0")

        assert isinstance(obj, Workflow)
        assert obj._id == "wf-uuid"
        assert obj._slug == "panneau-pub"
        assert obj._version == "0.3.0"
        # Should call the workflow registry lookup with parsed components.
        assert mock_req.call_args.args[:2] == (
            "GET",
            "/registry/lookup/workflow",
        )
        params = mock_req.call_args.kwargs["params"]
        assert params == {"owner": "acme", "slug": "panneau-pub", "version": "0.3.0"}

    def test_load_namespace_falls_back_to_package_on_workflow_404(self):
        client = make_client()
        registry_404 = NotFoundError("no workflow")
        package_resp = mock_response(
            200,
            {
                "kind": "package",
                "owner": "acme",
                "name": "core",
                "version": "0.2.0",
                "package_id": "pkg-uuid",
                "package_version_id": "pv-uuid",
                "function_name": None,
                "function_version_id": None,
            },
        )
        with patch.object(
            client,
            "_make_request",
            side_effect=[registry_404, package_resp],
        ) as mock_req:
            obj = client.load("acme/core")

        assert isinstance(obj, Package)
        assert obj._id == "pkg-uuid"
        assert obj._name == "core"
        # Fallback called the package lookup with ``name=`` (not ``slug=``).
        second_call = mock_req.call_args_list[1]
        assert second_call.args[:2] == ("GET", "/registry/lookup/package")
        assert second_call.kwargs["params"] == {"owner": "acme", "name": "core"}

    def test_load_namespace_no_version_omits_param(self):
        client = make_client()
        registry_resp = mock_response(
            200,
            {
                "kind": "workflow",
                "owner": "acme",
                "slug": "panneau-pub",
                "version": "0.1.0",
                "workflow_id": "wf-uuid",
                "version_id": "ver-uuid",
            },
        )
        with patch.object(client, "_make_request", return_value=registry_resp) as mock_req:
            client.load("acme/panneau-pub")

        params = mock_req.call_args.kwargs["params"]
        # No version → no ``version`` key.
        assert "version" not in params

    def test_load_without_namespace_path_raises_validation(self):
        """``client.load("foo")`` (no slash) is rejected — namespace-only API."""
        from mecapy.exceptions import ValidationError

        client = make_client()
        with pytest.raises(ValidationError, match="expected '{owner}/{name}"):
            client.load("e25-030-1")
