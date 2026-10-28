"""Check byte-for-byte reproducibility of unsigned Agent wheel and helper bundle."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from build_helper_bundle import build
from inspect_helper_bundle import inspect_bundle


def main() -> None:
    source = Path(__file__).resolve().parents[1] / "agent"
    with tempfile.TemporaryDirectory(prefix="commandcore-repro-") as temp:
        outputs = []
        for attempt in ("a", "b"):
            out = Path(temp) / attempt
            out.mkdir()
            env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(out),
                    str(source),
                ],
                check=True,
                env=env,
                stdout=subprocess.DEVNULL,
            )
            wheels = list(out.glob("commandcore_agent-*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("expected exactly one Agent wheel")
            wheel = wheels[0]
            bundle = out / "unsigned-helper.tar.gz"
            build(wheel, bundle, version="0.9.0-rc7-repro-test")
            inspect_bundle(bundle)
            outputs.append(
                (
                    hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    hashlib.sha256(bundle.read_bytes()).hexdigest(),
                )
            )
        if outputs[0] != outputs[1]:
            raise RuntimeError("unsigned wheel or helper bundle differs between builds")
        print("REPRODUCIBLE_UNSIGNED_HELPER_PASS", outputs[0])
        print("No signing, installation, or release authorization performed")


if __name__ == "__main__":
    main()
