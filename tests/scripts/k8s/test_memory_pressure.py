"""Tests for k8s memory_pressure script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_node(name: str, allocatable_memory: str = "16Gi", memory_pressure: bool = False) -> dict:
    """Create a mock node for testing."""
    return {
        "metadata": {"name": name},
        "status": {
            "allocatable": {"memory": allocatable_memory},
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True",
                },
                {
                    "type": "MemoryPressure",
                    "status": "True" if memory_pressure else "False",
                    "reason": "KubeletHasMemoryPressure" if memory_pressure else "KubeletHasSufficientMemory",
                    "message": "Memory pressure detected" if memory_pressure else "",
                },
            ],
        },
    }


def make_pod(
    name: str,
    namespace: str = "default",
    memory_request: str | None = "256Mi",
    memory_limit: str | None = "512Mi",
) -> dict:
    """Create a mock pod for testing."""
    resources = {}
    if memory_request:
        resources["requests"] = {"memory": memory_request}
    if memory_limit:
        resources["limits"] = {"memory": memory_limit}

    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "containers": [
                {
                    "name": "main",
                    "resources": resources,
                }
            ],
        },
    }


class TestMemoryPressure:
    """Tests for memory_pressure."""

    def test_healthy_cluster(self, capsys):
        """Healthy cluster returns exit code 0."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1"), make_node("node-2")]}
        pods = {
            "items": [
                make_pod("pod-1", memory_limit="512Mi"),
                make_pod("pod-2", memory_limit="256Mi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Nodes with memory pressure: 0" in captured.out

    def test_node_memory_pressure(self, capsys):
        """Node with memory pressure returns exit code 1."""
        from scripts.k8s.memory_pressure import run

        nodes = {
            "items": [
                make_node("node-1"),
                make_node("node-2", memory_pressure=True),
            ]
        }
        pods = {"items": [make_pod("pod-1", memory_limit="512Mi")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "node-2" in captured.out
        assert "PRESSURE" in captured.out

    def test_pods_without_limits(self, capsys):
        """Pods without limits returns exit code 1."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}
        pods = {
            "items": [
                make_pod("pod-1", memory_limit="512Mi"),
                make_pod("pod-no-limit", memory_limit=None),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "without memory limits: 1" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": [make_pod("pod-1", namespace="production", memory_limit="512Mi")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--namespace", "production"], output, context)

        assert result == 0

    def test_nodes_only(self, capsys):
        """Nodes-only flag skips pod analysis."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--nodes-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Node Memory Status" in captured.out
        assert "Pod Memory Summary" not in captured.out

    def test_pods_only(self, capsys):
        """Pods-only flag skips node analysis."""
        from scripts.k8s.memory_pressure import run

        pods = {"items": [make_pod("pod-1", memory_limit="512Mi")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--pods-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Pod Memory Summary" in captured.out
        assert "Node Memory Status" not in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": [make_pod("pod-1", memory_limit="512Mi")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "nodes" in data
        assert "pods" in data
        assert data["nodes"]["total"] == 1
        assert data["pods"]["total"] == 1

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2 and surfaces the error."""
        from scripts.k8s.memory_pressure import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        captured = capsys.readouterr()
        # Recorded errors must reach the user; previously they were silently
        # dropped because the script never called output.render() on the
        # early-return paths.
        assert "kubectl not found" in captured.out

    def test_kubectl_failure_surfaces_stderr(self, capsys):
        """When kubectl exits non-zero (e.g. missing kubeconfig), the stderr
        must reach the user instead of an empty stdout + bare rc=2."""
        import subprocess as _sp

        from scripts.k8s.memory_pressure import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): _sp.CompletedProcess(
                    args=["kubectl", "get", "nodes", "-o", "json"],
                    returncode=1,
                    stdout="",
                    stderr="Unable to connect to the server: cert error",
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        captured = capsys.readouterr()
        assert "kubectl failed" in captured.out
        assert "cert error" in captured.out

    def test_high_memory_pods_sorted(self, capsys):
        """High memory pods are sorted by usage."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}
        pods = {
            "items": [
                make_pod("small-pod", memory_limit="256Mi"),
                make_pod("large-pod", memory_limit="8Gi"),
                make_pod("medium-pod", memory_limit="2Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Large pod should be first
        top_consumers = data["pods"]["top_consumers"]
        assert len(top_consumers) > 0
        assert top_consumers[0]["pod"] == "large-pod"

    def test_namespace_aggregation(self, capsys):
        """Memory is aggregated by namespace."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1")]}
        pods = {
            "items": [
                make_pod("pod-1", namespace="production", memory_request="1Gi", memory_limit="2Gi"),
                make_pod("pod-2", namespace="production", memory_request="1Gi", memory_limit="2Gi"),
                make_pod("pod-3", namespace="staging", memory_request="512Mi", memory_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Production namespace should have 2 pods
        assert data["pods"]["by_namespace"]["production"]["count"] == 2
        assert data["pods"]["by_namespace"]["staging"]["count"] == 1

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.memory_pressure import run

        nodes = {"items": [make_node("node-1", memory_pressure=True)]}
        pods = {"items": [make_pod("pod-1", memory_limit=None)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes_with_pressure=1" in output.summary
        assert "pods_without_limits=1" in output.summary
