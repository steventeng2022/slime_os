"""Host regressions for embedded generation output isolation.

Run: python3 -m unittest discover -s tools/build -p 'test_*.py' -v

The real wrapper and generation writer run against temporary directories.
Component resolution and generation encoding are mocked, so no compiler runs.
These tests verify output handling, not generation validity or a guest boot.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


wrapper = load_script("generation_output_sel4", "scripts/build/build-sel4.py")
builder = load_script("generation_output_builder", "scripts/build/build-generation.py")
pc99_checker = load_script("generation_output_pc99", "scripts/check/check-sel4-x86-64-image.py")
REFUSAL = "embedded-only output directory contains boot-store.bin; use a fresh output directory"


class GenerationOutput(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="slime-generation-output-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest = {"generation": 1, "objects": [], "instances": [], "executables": []}
        self.payload = bytes(64)
        self.profile = builder.TARGET_PROFILES_BY_NAME["aarch64-sel4-qemu-virt"]
        self.calls = []
        for mocked in (
            patch.object(wrapper, "BUILD_ROOT", self.root),
            patch.object(wrapper, "run", self.run_generation),
            patch.object(builder, "resolve_component_sources", return_value=({}, [])),
            patch.object(builder, "build_generation", side_effect=lambda *args, **kwargs: self.payload),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_generation(self, command, **kwargs) -> None:
        self.calls.append((command, kwargs))
        self.assertIn("--generation-only", command)
        profile = builder.TARGET_PROFILES_BY_NAME[kwargs["environment"]["SLIME_TARGET_PROFILE"]]
        with redirect_stdout(io.StringIO()):
            builder.build_sel4_generation(Path(command[-1]), self.manifest, profile, generation_only=True)

    def legacy_outputs(self, directory: Path) -> dict[str, bytes]:
        directory.mkdir(parents=True)
        expected = {
            "boot-store.bin": b"legacy boot store",
            "generation.bin": b"previous generation",
            "unrelated.txt": b"preserve",
        }
        for name, content in expected.items():
            (directory / name).write_bytes(content)
        return expected

    def assert_preserved(self, directory: Path, expected: dict[str, bytes]) -> None:
        for name, content in expected.items():
            self.assertEqual((directory / name).read_bytes(), content, name)

    def assert_embedded_output(self, result: Path, parent: Path) -> None:
        self.assertEqual(result, parent / "embedded" / "generation.bin")
        self.assertEqual(result.read_bytes(), self.payload)
        self.assertEqual((result.parent / "generation-1.bin").read_bytes(), self.payload)
        self.assertFalse((result.parent / "boot-store.bin").exists())

    def test_default_build_preserves_legacy_outputs(self) -> None:
        parent = self.root / "sel4-generation"
        original = self.legacy_outputs(parent)

        result = wrapper.build_sel4_generation()

        self.assert_embedded_output(result, parent)
        self.assert_preserved(parent, original)

    def test_repeated_build_replaces_only_embedded_generations(self) -> None:
        parent = self.root / "sel4-generation"
        original = self.legacy_outputs(parent)
        first = wrapper.build_sel4_generation()
        self.payload = bytes([1]) * 64

        second = wrapper.build_sel4_generation()

        self.assertEqual(second, first)
        self.assert_embedded_output(second, parent)
        self.assert_preserved(parent, original)

    def test_custom_output_preserves_build_options(self) -> None:
        parent = self.root / "custom-output"
        original = self.legacy_outputs(parent)
        environment = {"ONLY_THIS": "preserved"}
        component_root = self.root / "component-specs"
        external = f"example={self.root / 'example.elf'}"

        result = wrapper.build_sel4_generation(
            "sel4-channel", output_name="custom-output", environment=environment,
            component_spec_root=component_root, external_components=[external],
        )

        self.assert_embedded_output(result, parent)
        self.assert_preserved(parent, original)
        self.assertEqual(environment, {"ONLY_THIS": "preserved"})
        command, kwargs = self.calls[-1]
        self.assertEqual(command[command.index("--component-spec-root") + 1], str(component_root))
        self.assertEqual(command[command.index("--external-component") + 1], external)
        self.assertEqual(kwargs["environment"]["SLIME_SEL4_MANIFEST"], "sel4-channel")
        self.assertEqual(kwargs["environment"]["ONLY_THIS"], "preserved")

    def test_platform_output_preserves_target_environment(self) -> None:
        platform = wrapper.QEMU_RISCV_VIRT
        parent = self.root / platform.name / "sel4-channel-generation"
        original = self.legacy_outputs(parent)

        result = wrapper.build_sel4_generation("sel4-channel", platform=platform)

        self.assert_embedded_output(result, parent)
        self.assert_preserved(parent, original)
        environment = self.calls[-1][1]["environment"]
        self.assertEqual(environment["SEL4_PREFIX"], str(platform.prefix_dir))
        self.assertEqual(environment["SLIME_TARGET_PROFILE"], platform.target_profile)

    def test_prebuilt_generation_skips_build(self) -> None:
        prebuilt = self.root / "prebuilt.bin"
        prebuilt.write_bytes(b"prebuilt generation")

        result = wrapper.build_sel4_generation(output_name="must-not-exist", prebuilt_generation=prebuilt)

        self.assertEqual(result, prebuilt)
        self.assertEqual(prebuilt.read_bytes(), b"prebuilt generation")
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / "must-not-exist").exists())

    def test_pc99_checker_reads_the_generated_file(self) -> None:
        platform = wrapper.QEMU_PC99
        parent = self.root / platform.name / "sel4-generation"
        original = self.legacy_outputs(parent)

        result = wrapper.build_sel4_generation(platform=platform)

        checked_path = self.root / pc99_checker.GENERATION_PATH.relative_to(ROOT / "build")
        self.assertEqual(checked_path, result)
        self.assertEqual(checked_path.read_bytes(), self.payload)
        self.assert_preserved(parent, original)

    def test_direct_writer_refuses_existing_boot_store(self) -> None:
        output = self.root / "direct-output"
        original = self.legacy_outputs(output)

        with self.assertRaises(SystemExit) as refusal:
            builder.build_sel4_generation(output, self.manifest, self.profile, generation_only=True)

        self.assertEqual(str(refusal.exception), REFUSAL)
        self.assert_preserved(output, original)

    def test_embedded_output_collision_keeps_store_and_generation(self) -> None:
        parent = self.root / "sel4-generation"
        original = self.legacy_outputs(parent)
        result = wrapper.build_sel4_generation()
        previous_generation = result.read_bytes()
        store = result.parent / "boot-store.bin"
        store.write_bytes(b"do not remove this store")
        self.payload = bytes([2]) * 64

        with self.assertRaises(SystemExit) as refusal:
            wrapper.build_sel4_generation()

        self.assertEqual(str(refusal.exception), REFUSAL)
        self.assertEqual(result.read_bytes(), previous_generation)
        self.assertEqual(store.read_bytes(), b"do not remove this store")
        self.assert_preserved(parent, original)


if __name__ == "__main__":
    unittest.main()
