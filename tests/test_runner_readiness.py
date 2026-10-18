import importlib.util
from pathlib import Path


def test_runner_isolation(tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts/runner_readiness.py"
    spec = importlib.util.spec_from_file_location("runner_readiness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.evaluate(
            uid=1000, root=False, docker_access=False, runner_dir=tmp_path, services=[]
        )
        == []
    )
    assert module.evaluate(
        uid=0, root=True, docker_access=True, runner_dir=tmp_path, services=[]
    )
    assert module.evaluate(
        uid=1000,
        root=False,
        docker_access=False,
        runner_dir=tmp_path,
        services=["actions.runner.example.service"],
    )


def test_privileged_groups_block(tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts/runner_readiness.py"
    spec = importlib.util.spec_from_file_location("runner_readiness_groups", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.evaluate(
        uid=1001,
        root=False,
        docker_access=False,
        runner_dir=tmp_path,
        services=[],
        groups={"users", "docker"},
    )
    assert "runner account belongs to privileged groups" in result
