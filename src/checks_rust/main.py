"""Rust build checks for viporlab repos (Dagger module).

Language-specific module per the TrueNorth per-language-module decision
(FR-19): a cargo-workspace build runs entirely inside the engine (no runner
toolchain — FR-73/FR-7/NFR-4). Contract-compatible with dagger-checks-c: the
machinery dispatches `dagger call --mod <module> build --source=.`, scans the
job log for `TRUENORTH_RESULT: {json}`, and reads `details.digest` for the
build -> test handoff.

Why a separate module: a Rust workspace's canonical build is `cargo build`
driven through the project's own Dockerfile (per-bin ARG app). dagger-checks-c
is autotools; dagger-checks is scans only. Nothing Rust existed before this.

BUILD PATH (dockerfile-driven, mirrors dagger-checks-c PATH A):

    1. `docker_build(dockerfile, target=<builder stage>, build_args)` — builds
       up to the stage that holds target/release/<bin> (a shell-bearing rust
       image, so probes can exec).
    2. ARTIFACT GATE — ELF magic at `rust-build.artifact_path` inside that
       stage. No binary -> status=fail at stage=artifact-gate, hard fail.
    3. version probe (`<bin> --version`) — reported, never fatal (a
       dynamically-linked binary in a slim builder may miss libs).
    4. IMAGE SCAN (optional) — syft SBOM + grype CVE gate on the FINAL image,
       BEFORE any staging tag is pushed (fail means no tag -> the Kargo
       warehouse never sees the artifact).
    5. PUBLISH (optional) — push the FINAL image by digest to
       `rust-build.publish` as `<repo>:sha-<commit>[-<variant>]`.

Repo-side control block (TOP LEVEL in .github/truenorth.yaml, on purpose:
keys under checks: are fanned out as jobs by the harness — a checks.* key
dispatches a phantom `dagger call <key>`; a top-level block is invisible to
the harness and read only here):

    rust-build:
      app: xelis_daemon
      binary: xelis_daemon
      dockerfile: Dockerfile
      target: builder
      artifact_path: /tmp/xelis-build/target/release/xelis_daemon
      publish: zot.viporlab.net/demo/xelis-staging
      scan:
        enabled: true
        fail_on: high,critical
        ignore_unfixed: true
        sbom_repo: registry.viporlab.net/demo/xelis-sbom

Absent block: defaults app=xelis_daemon, binary=<app>, dockerfile=Dockerfile,
target=builder, artifact_path=/tmp/xelis-build/target/release/<binary>,
publish="" (no staging tag), scan disabled.

Run: dagger call --mod github.com/snoby-demo-org/dagger-checks-rust build --source=.
"""

import json
import re

import dagger
from dagger import dag, function, object_type

DEFAULT_APP = "xelis_daemon"
DEFAULT_DOCKERFILE = "Dockerfile"
DEFAULT_TARGET = "builder"
DEFAULT_BUILD_DIR = "/tmp/xelis-build"

_SEV_ORDER = {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_outer_quotes(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        return val[1:-1]
    return val


def _parse_rust_build(text: str) -> dict:
    """Extract the top-level `rust-build:` block (flat keys + one nested `scan:`).

    Line-based on purpose: the module runs in the SDK image, which ships no
    PyYAML. Nested `scan:` is a single level, matching the block shape above.
    """
    cfg: dict = {"scan": {}}
    in_block = False
    block_indent = 0
    section = None
    section_indent = 0
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = _indent(raw)
        line = raw.strip()
        if not in_block:
            if line.startswith("rust-build:"):
                in_block = True
                block_indent = indent
            continue
        if indent <= block_indent and not line.startswith("-"):
            break  # left the block
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.split(" #")[0].strip() if val else ""
        if not val:
            section = key
            section_indent = indent
            if key == "scan":
                cfg.setdefault("scan", {})
            continue
        if section == "scan" and indent > section_indent:
            cfg["scan"][key] = _strip_outer_quotes(val)
            continue
        section = None
        cfg[key] = _strip_outer_quotes(val)
    return cfg


def _bool(val, default: bool) -> bool:
    if val is None or val == "":
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


async def _commit_sha(source: dagger.Directory) -> str:
    """Commit sha for tagging. Dagger excludes .git from directory sync, so CI
    checkouts can't `git rev-parse`; the machinery's .truenorth_commit is read
    first, with a git fallback for local fixtures."""
    try:
        return (await source.file(".truenorth_commit").contents()).strip()
    except Exception:  # noqa: BLE001
        pass
    try:
        return (
            await dag.container()
            .from_("alpine:3.20")
            .with_exec(["apk", "add", "--no-cache", "git"])
            .with_mounted_directory("/src", source)
            .with_workdir("/src")
            .with_exec(["git", "rev-parse", "HEAD"])
            .stdout()
        ).strip()
    except Exception:  # noqa: BLE001 — no .git (local fixture) -> sha-less tag
        return ""


@object_type
class ChecksRust:
    @function
    async def build(self, source: dagger.Directory, variant: str = "") -> str:
        """REAL — the Rust BUILD LEG: project Dockerfile (per-bin ARG app) ->
        artifact gate -> optional image scan -> optional staging publish.

        Fails when the docker build fails, when the artifact gate finds no ELF
        binary at `rust-build.artifact_path`, when the image scan trips
        fail-on severities, or when the staging publish fails. Warnings are
        reported, never fatal.

        `variant` is accepted for workflow-matrix compatibility (the harness
        passes --variant=<id> only when truenorth.yaml declares a build
        matrix); it is recorded in the payload and the staging tag.
        """
        try:
            cfg = _parse_rust_build(await source.file(".github/truenorth.yaml").contents())
        except Exception:  # noqa: BLE001 — no/unreadable control block -> defaults
            cfg = {"scan": {}}

        app = cfg.get("app") or DEFAULT_APP
        binary = cfg.get("binary") or app
        dockerfile = cfg.get("dockerfile") or DEFAULT_DOCKERFILE
        target = cfg.get("target") or DEFAULT_TARGET
        artifact_path = cfg.get("artifact_path") or f"{DEFAULT_BUILD_DIR}/target/release/{binary}"
        publish_repo = str(cfg.get("publish") or "").rstrip("/")
        scan_cfg = cfg.get("scan") or {}

        sha = await _commit_sha(source)
        bargs = [
            dagger.BuildArg(name="app", value=app),
            dagger.BuildArg(name="commit_hash", value=sha or "unknown"),
        ]

        # ---- 1. builder stage: the cargo-chef "builder" target holds
        # target/release/<bin> on a shell-bearing image (probe-able).
        builder = await source.docker_build(
            dockerfile=dockerfile,
            target=target,
            build_args=bargs,
            secrets=[],
        )

        # ---- 2. artifact gate: ELF magic (exec probe — the binary exceeds
        # Dagger's file-contents read limit, so .contents() is not an option).
        try:
            magic = (
                await builder.with_entrypoint([])
                .with_exec(["sh", "-c", f"head -c 4 {artifact_path} | od -An -tx1 | tr -d ' \\n'"])
                .stdout()
            ).strip()
        except Exception as e:  # noqa: BLE001 — a missing path surfaces here
            raise RuntimeError(
                f"build FAILED at stage=artifact-gate: cannot read {artifact_path} "
                f"from dockerfile={dockerfile} target={target} app={app}\n{e}"
            ) from e
        if magic != "7f454c46":
            raise RuntimeError(
                f"build FAILED at stage=artifact-gate: {artifact_path} in the target "
                f"image is not an ELF binary (magic={magic!r}) — check "
                f"rust-build.app/binary/artifact_path in .github/truenorth.yaml "
                f"(app ARG={app}, expected binary xelis_<app>)"
            )

        # ---- 3. version probe: reported, never fatal (slim builder may lack
        # runtime libs for a dynamically-linked artifact).
        try:
            version = (
                await builder.with_entrypoint([])
                .with_exec(["sh", "-c", f"{artifact_path} --version 2>&1 | head -1"])
                .stdout()
            ).strip()
        except Exception:  # noqa: BLE001
            version = ""

        payload = {
            "check": "build",
            "tool": f"docker-build@{dockerfile}#{target}",
            "status": "pass",
            "failed_stage": None,
            "warnings": 0,
            "binary": version or None,
            "app": app,
        }
        if variant:
            payload["variant"] = variant

        lines = [
            "=" * 50,
            f" [build] cargo via {dockerfile} (target={target}, app={app})",
        ]
        if version:
            lines.append(f"  version: {version[:100]}")

        # ---- 4. final image (needed for scan/publish); build it once.
        img = None
        if publish_repo or _bool(scan_cfg.get("enabled"), False):
            img = await source.docker_build(
                dockerfile=dockerfile,
                build_args=bargs,
                secrets=[],
            )

        # ---- 5. image scan (syft SBOM + grype CVE gate) before any staging tag
        if img is not None and _bool(scan_cfg.get("enabled"), False):
            fail_on = [s.strip().lower() for s in str(scan_cfg.get("fail_on", "high,critical")).split(",") if s.strip()]
            ignore_unfixed = _bool(scan_cfg.get("ignore_unfixed"), True)
            sbom_repo = str(scan_cfg.get("sbom_repo", "")).rstrip("/")
            lines.append("=" * 50)
            lines.append(f" [build] image scan (syft+grype, fail_on={','.join(fail_on)}"
                         f"{' , ignore-unfixed' if ignore_unfixed else ''})")
            try:
                tar_f = img.as_tarball()
                syft_ctr = (
                    dag.container()
                    .from_("alpine:3.20")
                    .with_file("/bin/syft", dag.container().from_("anchore/syft:latest").file("/syft"))
                    .with_mounted_file("/scan/scan.img", tar_f)
                    .with_exec(["sh", "-c",
                                "mkdir -p /out && syft /scan/scan.img -o cyclonedx-json --file /out/sbom.json"])
                )
                sbom_f = syft_ctr.file("/out/sbom.json")
                top_sev = max(fail_on, key=lambda s: _SEV_ORDER.get(s, 9))
                grype_ctr = (
                    dag.container()
                    .from_("alpine:3.20")
                    .with_file("/bin/grype", dag.container().from_("anchore/grype:latest").file("/grype"))
                    .with_mounted_file("/scan/scan.img", tar_f)
                    .with_mounted_cache("/grype-db", dag.cache_volume("grype-db"))
                    .with_env_variable("GRYPE_DB_CACHE_DIR", "/grype-db")
                    .with_exec(["sh", "-c",
                                "mkdir -p /out && grype /scan/scan.img -o json --file /out/grype.json "
                                f"--fail-on {top_sev} {'--only-fixed' if ignore_unfixed else ''}"],
                               expect=dagger.ReturnType.ANY)
                )
                report = json.loads(await grype_ctr.file("/out/grype.json").contents())
                matches = report.get("matches", [])
                counts: dict = {}
                for m in matches:
                    sev = ((m.get("vulnerability") or {}).get("severity") or "unknown").lower()
                    counts[sev] = counts.get(sev, 0) + 1
                failing = {s: counts.get(s, 0) for s in fail_on if counts.get(s)}
                lines.append(f"  vulnerabilities: {len(matches)} matched"
                             + (f"; failing: {failing}" if failing else "; none at fail-on severity"))
                if sbom_repo:
                    addr = f"{sbom_repo}:sha-{sha or 'unknown'}"
                    await (
                        dag.container().from_("alpine:3.20")
                        .with_file("/sbom.json", sbom_f)
                        .publish(addr)
                    )
                    payload["sbom"] = addr
                    lines.append(f"  sbom: {addr}")
                payload["scan"] = {"status": "fail" if failing else "pass",
                                   "counts": counts, "total": len(matches)}
                if failing:
                    raise RuntimeError(
                        f"build FAILED at stage=image-scan: vulnerabilities at fail-on "
                        f"severity ({', '.join(f'{k}={v}' for k, v in failing.items())})\n"
                        f"  no staging tag was pushed; bump the base image or adjust "
                        f"rust-build.scan in truenorth.yaml")
            except RuntimeError:
                raise
            except Exception as e:  # noqa: BLE001 — scan infrastructure failure is a hard fail
                raise RuntimeError(f"build FAILED at stage=image-scan (infrastructure): {e}") from e

        # ---- 6. staging publish by digest (promotion-not-rebuild)
        if publish_repo and img is not None:
            tag = "sha-" + (sha or "unknown") + (f"-{variant}" if variant else "")
            addr = f"{publish_repo}:{tag}"
            lines.append(f"  staging: publishing gated image -> {addr}")
            digest = await img.publish(addr)
            payload["digest"] = digest
            payload["staging"] = addr
            lines.append(f"  staged: {addr}@{digest}")

        lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
        lines.append("=" * 50)
        return "\n".join(lines)

    @function
    async def lint(self, source: dagger.Directory) -> str:
        """Advisory — `cargo clippy` over the workspace via the Dockerfile's
        builder target. Declares status=fail when any clippy *error* is
        present; warnings are counted only (the truenorth.yaml mode decides
        blocking). Compiles the workspace — expect heavy-tier timings cold.
        """
        cfg = {"scan": {}}
        try:
            cfg = _parse_rust_build(await source.file(".github/truenorth.yaml").contents())
        except Exception:  # noqa: BLE001
            pass
        app = cfg.get("app") or DEFAULT_APP
        dockerfile = cfg.get("dockerfile") or DEFAULT_DOCKERFILE
        target = cfg.get("target") or DEFAULT_TARGET
        sha = await _commit_sha(source)
        builder = await source.docker_build(
            dockerfile=dockerfile,
            target=target,
            build_args=[dagger.BuildArg(name="app", value=app),
                        dagger.BuildArg(name="commit_hash", value=sha or "unknown")],
            secrets=[],
        )
        tool = builder.with_entrypoint([]).with_exec(
            ["sh", "-c", "rustup component add clippy 2>&1 | tail -2"])
        out = await (
            tool
            .with_workdir(DEFAULT_BUILD_DIR)
            .with_exec(["sh", "-c",
                        "cargo clippy --workspace --all-targets --message-format=short 2>&1 "
                        "| tail -400; true"])
            .stdout()
        )
        errors = sum(1 for ln in out.splitlines() if ln.startswith("error"))
        warnings = sum(1 for ln in out.splitlines() if ln.startswith("warning"))
        payload = {"check": "lint", "tool": "cargo-clippy", "errors": errors,
                   "warnings": warnings, "status": "fail" if errors else "pass"}
        lines = ["=" * 50, " [lint] cargo clippy --workspace",
                 f"  errors: {errors}  warnings: {warnings}"]
        lines += ["  " + ln[:160] for ln in out.splitlines()[:40]]
        lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
        lines.append("=" * 50)
        if errors:
            print(f"::warning::cargo clippy: {errors} error(s) (declared status=fail)")
        return "\n".join(lines)

    @function
    async def format(self, source: dagger.Directory) -> str:
        """Advisory — `cargo fmt --check` (no compile, fast tier)."""
        cfg = {"scan": {}}
        try:
            cfg = _parse_rust_build(await source.file(".github/truenorth.yaml").contents())
        except Exception:  # noqa: BLE001
            pass
        dockerfile = cfg.get("dockerfile") or DEFAULT_DOCKERFILE
        target = cfg.get("target") or DEFAULT_TARGET
        sha = await _commit_sha(source)
        builder = await source.docker_build(
            dockerfile=dockerfile,
            target=target,
            build_args=[dagger.BuildArg(name="app", value=cfg.get("app") or DEFAULT_APP),
                        dagger.BuildArg(name="commit_hash", value=sha or "unknown")],
            secrets=[],
        )
        ctr = builder.with_entrypoint([]).with_exec(
            ["sh", "-c", "rustup component add rustfmt 2>&1 | tail -2"])
        out = await (
            ctr.with_workdir(DEFAULT_BUILD_DIR)
            .with_exec(["sh", "-c",
                        "cargo fmt --all -- --check >/tmp/fmt.log 2>&1; echo EXIT:$?; "
                        "grep -c 'Diff in' /tmp/fmt.log || true; tail -40 /tmp/fmt.log"],
                       expect=dagger.ReturnType.ANY)
            .stdout()
        )
        m = re.search(r"EXIT:(\d+)", out)
        rc = int(m.group(1)) if m else 1
        diffs = 0
        for ln in out.splitlines():
            if ln.strip().isdigit():
                diffs = int(ln.strip())
                break
        payload = {"check": "format", "tool": "cargo-fmt", "status": "fail" if rc else "pass",
                   "diffs": diffs}
        lines = ["=" * 50, f" [format] cargo fmt --check (rc={rc}, diffs={diffs})"]
        lines += ["  " + ln[:160] for ln in out.splitlines()[:40]]
        lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
        lines.append("=" * 50)
        return "\n".join(lines)
