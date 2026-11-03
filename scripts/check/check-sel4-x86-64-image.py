#!/usr/bin/env python3
"""P6.1: the admitted, reproducible x86-64 seL4 build, without a boot claim.

Deliberately not a QEMU check. P6.1's exit condition is that the repository
reproducibly builds an *admitted* x86-64 seL4 kernel, root task, child fixture,
and generation for one pinned pc99 profile; booting them is P6.2's, and this
platform has no packaged image to boot because it is on seL4's native
Multiboot2 route.

Three things are asserted:

  * the built artifacts really are x86-64 and really carry the pc99 profile's
    exact qualification;
  * a wrong architecture, ABI, page profile, machine, or profile identity is
    refused before any executable byte is mapped;
  * two normalized builds produce byte-identical kernel, root, child,
    generation, and identity artifacts, and the AArch64 and RV64 profiles keep
    their own identities.

Run `scripts/build/build-sel4.py --platform qemu-pc99` first; this reads what
that produced rather than rebuilding it, except for the reproducibility case,
which rebuilds deliberately.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from harness import ROOT, load_qemu_profile, sha256_file  # noqa: E402
from pc99_media import PINS_SECTION, boot_media  # noqa: E402

import boot_contracts  # noqa: E402

PLATFORM = "qemu-pc99"
PROFILE_NAME = "x86_64-sel4-qemu-pc99"
FRAMEWORK_PROFILE_NAME = "x86_64-sel4-framework13-ai300"
MANIFEST_PATH = ROOT / "build" / f"slime-sel4-{PLATFORM}.identity.json"
GENERATION_PATH = ROOT / "build" / PLATFORM / "sel4-generation" / "embedded" / "generation.bin"
PINS_PATH = ROOT / "sel4" / "pins.toml"
BUILD_SEL4 = ROOT / "scripts" / "build" / "build-sel4.py"

# `e_machine` for x86-64, from the ELF specification. Asserted against the
# profile's own `elf_machine` too, so the contract and this check cannot drift
# apart silently.
EM_X86_64 = 62
ET_EXEC = 2

failures: list[str] = []


def record(message: str) -> None:
    failures.append(message)


def fail(message: str) -> None:
    raise SystemExit(f"x86-64 seL4 image check: {message}")


def read_manifest() -> dict[str, object]:
    if not MANIFEST_PATH.is_file():
        fail(
            f"missing {MANIFEST_PATH.relative_to(ROOT)}; run "
            f"`python3 scripts/build/build-sel4.py --platform {PLATFORM}` first"
        )
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"cannot parse {MANIFEST_PATH.relative_to(ROOT)}: {error}")


def elf_header(path: Path) -> tuple[int, int]:
    """Return one ELF64 little-endian executable's `e_type` and `e_machine`."""
    data = path.read_bytes()[:24]
    if len(data) < 24 or data[:4] != b"\x7fELF":
        fail(f"{path.relative_to(ROOT)} is not an ELF file")
    if data[4] != 2 or data[5] != 1:
        fail(f"{path.relative_to(ROOT)} is not ELF64 little-endian")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    return e_type, e_machine


def check_profile_contract() -> boot_contracts.TargetProfile:
    """The generated contract must describe the profile this platform builds."""
    profile = boot_contracts.TARGET_PROFILES_BY_NAME.get(PROFILE_NAME)
    if profile is None:
        fail(f"the target-profile contract does not declare {PROFILE_NAME}")
    framework = boot_contracts.TARGET_PROFILES_BY_NAME.get(FRAMEWORK_PROFILE_NAME)
    if framework is None:
        fail(f"the target-profile contract does not declare {FRAMEWORK_PROFILE_NAME}")
    if profile.architecture != boot_contracts.ARCH_X86_64:
        record(f"{PROFILE_NAME} architecture is {profile.architecture}, expected x86-64")
    if profile.abi != boot_contracts.ABI_SLIME_X86_64_SEL4_V1:
        record(f"{PROFILE_NAME} must use the x86-64 seL4 ABI, not {profile.abi}")
    if profile.page_profile != boot_contracts.PAGE_PROFILE_X86_64_4K:
        record(f"{PROFILE_NAME} page profile is {profile.page_profile}, expected x86-64 4K")
    if profile.elf_machine != EM_X86_64:
        record(f"{PROFILE_NAME} elf_machine is {profile.elf_machine}, expected {EM_X86_64}")
    if profile.page_bytes != 4096:
        record(f"{PROFILE_NAME} page size is {profile.page_bytes}, expected 4096")
    expected_features = (
        boot_contracts.FEATURE_X86_64_BASELINE | boot_contracts.FEATURE_X86_64_SEL4
    )
    if profile.required_features != expected_features:
        record(
            f"{PROFILE_NAME} required features are {profile.required_features}, "
            f"expected {expected_features}"
        )
    # The retired custom kernel's identity must stay distinct: it is retained
    # only so rollback-window artifacts still decode, and reusing any part of
    # it would make two incompatible ABIs look interchangeable.
    retired = boot_contracts.TARGET_PROFILES_BY_NAME.get("x86_64-qemu-virtio")
    if retired is None:
        record("the retained x86_64-qemu-virtio rollback profile disappeared")
    else:
        if retired.id == profile.id or retired.abi == profile.abi:
            record("the pc99 profile reuses the retired custom-kernel identity")
        if retired.required_features == profile.required_features:
            record("the pc99 profile reuses the retired custom-kernel feature set")
    # Same platform contract, different exact platform: P6.6 owns the physical
    # claim, and sharing an identity would let a QEMU artifact satisfy it.
    if framework.id == profile.id or framework.name == profile.name:
        record("the Framework profile is not a distinct identity from the pc99 reference")
    if framework.abi != profile.abi:
        record("the Framework profile should share the pc99 userspace ABI")
    if framework.qemu_binary != "":
        record("the Framework profile must name no emulator")
    return profile


def check_manifest(manifest: dict[str, object], profile: boot_contracts.TargetProfile) -> None:
    if manifest.get("platform") != PLATFORM:
        record(f"identity names platform {manifest.get('platform')!r}, expected {PLATFORM!r}")
    if manifest.get("target_profile") != PROFILE_NAME:
        record(
            f"identity names target {manifest.get('target_profile')!r}, expected {PROFILE_NAME!r}"
        )
    # The boot-route field's whole point: this platform must not claim a
    # packaged image, because the Multiboot2 route has none. What it must claim
    # instead is the EFI file tree P6.2 assembles, whose digest is the identity
    # a boot binds to the way the loader platforms bind a packaged ELF.
    if manifest.get("boot_route") != "multiboot2":
        record(f"identity boot route is {manifest.get('boot_route')!r}, expected 'multiboot2'")
    if "image" in manifest:
        record("identity claims a packaged image; the Multiboot2 route has none")
    media = manifest.get("media")
    if not isinstance(media, dict):
        record("identity records no boot media tree")
    else:
        if not isinstance(media.get("tree_sha256"), str):
            record("identity records no boot media tree digest")
        files = media.get("files")
        if not isinstance(files, dict):
            record("identity records no boot media file table")
        else:
            observed = boot_media(
                ROOT / str(media["tree"]),
                profile=load_qemu_profile(fail, PINS_PATH, PINS_SECTION),
                fail=fail,
            )
            if observed["tree_sha256"] != media["tree_sha256"]:
                record(
                    f"boot media tree digest is {observed['tree_sha256']}, "
                    f"identity records {media['tree_sha256']}"
                )
            for relative, entry in files.items():
                if observed["files"].get(relative) != entry:
                    record(f"boot media file {relative} does not match the identity")
    # The firmware and bootloader are not built here, so what the identity can
    # bind is the pins they were verified against. Absent, a boot claim would
    # name no firmware at all.
    inputs = manifest.get("boot_inputs")
    if not isinstance(inputs, dict):
        record("identity records no firmware or bootloader identity")
    else:
        for required in ("firmware_code_sha256", "grub_modules_sha256"):
            if not isinstance(inputs.get(required), str):
                record(f"identity boot inputs record no {required}")
    elf = manifest.get("elf")
    if not isinstance(elf, dict):
        fail("identity has no `elf` section")
    for absent in ("loader", "payload_tool"):
        if absent in elf:
            record(f"identity records a {absent} the Multiboot2 route does not build")
    for required in ("kernel", "root", "child"):
        if required not in elf:
            record(f"identity does not record the {required} ELF")
    config = manifest.get("config")
    if not isinstance(config, dict):
        fail("identity has no `config` section")
    # An x86 machine describes itself through ACPI, so there is no device tree
    # or generated platform description to record. Claiming either would make
    # the identity assert about files the prefix does not contain.
    for absent in ("dtb", "platform_info"):
        if absent in config:
            record(f"identity records a {absent} seL4 pc99 does not generate")
    # Every executable the identity records must actually be x86-64.
    for key in ("kernel", "root", "child"):
        entry = elf.get(key)
        if not isinstance(entry, dict):
            continue
        path = ROOT / str(entry["path"])
        if not path.is_file():
            record(f"identity records a missing {key} at {entry['path']}")
            continue
        e_type, e_machine = elf_header(path)
        if e_machine != profile.elf_machine:
            record(
                f"{key} ELF e_machine is {e_machine}, expected {profile.elf_machine} "
                f"for {PROFILE_NAME}"
            )
        if e_type != ET_EXEC:
            record(f"{key} ELF is not ET_EXEC (got {e_type})")
        actual = sha256_file(path, fail)
        if actual != entry["sha256"]:
            record(f"{key} ELF hash is {actual}, identity records {entry['sha256']}")
    generation = manifest.get("generation")
    if not isinstance(generation, dict) or "identity" not in generation:
        record("identity records no embedded generation")


def check_generation_target(profile: boot_contracts.TargetProfile) -> None:
    """Every executable in the built generation must carry this exact profile."""
    if not GENERATION_PATH.is_file():
        fail(
            f"missing {GENERATION_PATH.relative_to(ROOT)}; run "
            f"`python3 scripts/build/build-sel4.py --platform {PLATFORM}` first"
        )
    data = GENERATION_PATH.read_bytes()
    header = boot_contracts.COMPONENT_IMAGE_HEADER
    magic = boot_contracts.COMPONENT_IMAGE_ELF_MAGIC
    found = 0
    offset = data.find(magic)
    while offset != -1:
        if offset + header.size <= len(data):
            fields = header.unpack_from(data, offset)
            (
                _magic,
                _version,
                _header_len,
                _kernel_abi,
                architecture,
                abi,
                page_profile,
                _reserved0,
                _reserved1,
                _reserved2,
                _stack,
                profile_id,
                required_features,
            ) = fields
            # Only count headers whose profile id resolves: the magic can also
            # appear inside a component's own payload bytes by coincidence.
            if profile_id in boot_contracts.TARGET_PROFILES_BY_ID:
                found += 1
                if profile_id != profile.id:
                    record(
                        f"a generation executable is qualified for profile {profile_id}, "
                        f"expected {profile.id} ({PROFILE_NAME})"
                    )
                if architecture != profile.architecture:
                    record(f"a generation executable declares architecture {architecture}")
                if abi != profile.abi:
                    record(f"a generation executable declares ABI {abi}")
                if page_profile != profile.page_profile:
                    record(f"a generation executable declares page profile {page_profile}")
                if required_features != profile.required_features:
                    record(f"a generation executable declares features {required_features}")
        offset = data.find(magic, offset + 1)
    if found == 0:
        record("the built generation embeds no recognizable component-image header")
    print(f"x86-64 seL4 image check: {found} embedded executables carry {PROFILE_NAME}")


def check_wrong_target_refusal() -> None:
    """Byte-level target admission must refuse every wrong qualification.

    This is delegated to `cargo test -p boot-contracts` rather than restated
    here. `an_x86_64_sel4_payload_refuses_every_wrong_qualification` constructs
    an image for this profile and offers it to a different architecture, the
    retired custom-kernel x86 ABI, the physical Framework machine profile, and
    a perturbation of each individual header axis, asserting the *distinct*
    error each reports.

    A Python re-implementation would have to build a mis-qualified generation
    and observe the builder exit nonzero, which is a weaker claim: the builder
    also exits nonzero for a spec-digest mismatch, a missing prefix, and a
    dozen unrelated reasons, so a green result would not be evidence that
    target admission is what refused it.
    """
    process = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(ROOT / "boot-contracts" / "Cargo.toml"),
            "--all-features",
            "--",
            "--exact",
            "component_image::tests::an_x86_64_sel4_payload_refuses_every_wrong_qualification",
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if process.returncode != 0:
        record("x86-64 target admission negatives failed:\n" + process.stdout)
        return
    if "1 passed" not in process.stdout:
        record(
            "the x86-64 target-admission test did not run; a rename would make "
            "this gate vacuous:\n" + process.stdout
        )
        return
    print(
        "x86-64 seL4 image check: wrong architecture, ABI, page profile, machine "
        "profile, and feature set each refused with a distinct error"
    )


def check_reproducible() -> None:
    """Two normalized full builds must produce byte-identical artifacts.

    P6.1 requires this of the kernel, root, child, generation, *and* identity
    artifacts, so the whole platform build is run twice rather than only the
    generation step: nondeterminism in the seL4 CMake build, either Rust ELF,
    the freestanding C component, or the identity JSON would otherwise pass a
    generation-only comparison.

    The first run's artifacts are snapshotted before the second overwrites
    them, because both runs write to the same platform-qualified output paths.
    """
    tracked = {
        "kernel": ROOT / "build" / "sel4-pc99-prefix" / "bin" / "kernel.elf",
        "root": ROOT / "build" / "sel4-artifacts" / PLATFORM / "slime-root.elf",
        "child": ROOT / "build" / "sel4-artifacts" / PLATFORM / "slime-root-child.elf",
        "component": ROOT / "build" / "slisp-product-x86_64.elf",
        "generation": GENERATION_PATH,
        "identity": MANIFEST_PATH,
        # P6.2's EFI tree is what a boot reads, so it belongs here beside the
        # artifacts it contains. Its per-file digests are folded into the
        # identity, but comparing the identity alone would not catch a tree
        # that changed *and* was faithfully described both times.
        "boot media": ROOT / "build" / "media" / PLATFORM / "EFI" / "BOOT" / "BOOTX64.EFI",
        "grub config": ROOT / "build" / "media" / PLATFORM / "boot" / "grub" / "grub.cfg",
    }
    rounds = []
    for round_index in (1, 2):
        process = subprocess.run(
            [
                sys.executable,
                str(BUILD_SEL4),
                "--platform",
                PLATFORM,
                "--skip-pin-check",
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if process.returncode != 0:
            fail(f"reproducibility build {round_index} failed:\n{process.stdout}")
        digests = {}
        for name, path in tracked.items():
            if not path.is_file():
                fail(f"reproducibility build {round_index} produced no {name} at {path}")
            digests[name] = sha256_file(path, fail)
        rounds.append(digests)
    differing = sorted(name for name in tracked if rounds[0][name] != rounds[1][name])
    if differing:
        record(
            "two normalized builds differ in "
            + ", ".join(f"{name} ({rounds[0][name][:16]}… vs {rounds[1][name][:16]}…)" for name in differing)
        )
        return
    print(
        "x86-64 seL4 image check: two normalized builds are byte-identical across "
        + ", ".join(sorted(tracked))
    )


def check_other_architectures_unchanged(profile: boot_contracts.TargetProfile) -> None:
    """The retained profiles must keep their own distinct identities."""
    for name in ("aarch64-sel4-qemu-virt", "riscv64-sel4-qemu-virt", "riscv64-sel4-milkv-duo"):
        other = boot_contracts.TARGET_PROFILES_BY_NAME.get(name)
        if other is None:
            record(f"the retained profile {name} disappeared")
            continue
        if other.id == profile.id:
            record(f"{name} collides with {PROFILE_NAME} on profile id")
        if other.architecture == profile.architecture:
            record(f"{name} unexpectedly declares the x86-64 architecture")
        if other.abi == profile.abi:
            record(f"{name} unexpectedly declares the x86-64 seL4 ABI")


def main() -> None:
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    profile = check_profile_contract()
    check_manifest(read_manifest(), profile)
    check_generation_target(profile)
    check_other_architectures_unchanged(profile)
    check_wrong_target_refusal()
    check_reproducible()
    if failures:
        raise SystemExit(
            "x86-64 seL4 image check failed:\n" + "\n".join(f"  - {item}" for item in failures)
        )
    print(
        "x86-64 seL4 image check: admitted and reproducible kernel, root, child, and "
        f"generation for {PROFILE_NAME}; no boot claim"
    )


if __name__ == "__main__":
    main()
