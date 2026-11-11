# dagger-checks-rust

TrueNorth per-language build module for **Rust / cargo workspaces** (FR-19).
Engine: Dagger; SDK: Python. Pinned by tag from repo `.github/truenorth.yaml`:

```yaml
checks:
  build:
    enabled: true
    mode: blocking
    tier: heavy
    plane: build
    module: github.com/snoby-demo-org/dagger-checks-rust@v0.1.0
```

Contract-compatible with `dagger-checks-c`: the machinery dispatches
`dagger call --mod <module> build --source=.`, reads `TRUENORTH_RESULT: {json}`
from the job log, and takes `details.digest` for the build → test handoff.

## Functions

| function | purpose |
|---|---|
| `build` | project Dockerfile (per-bin `ARG app`) → builder stage → ELF artifact gate → optional syft/grype image scan → optional staging publish by digest |
| `lint` | `cargo clippy --workspace --all-targets` (compiles; advisory until a baseline exists) |
| `format` | `cargo fmt --all -- --check` (no compile; fast tier) |

## Repo-side control block

Top level in `.github/truenorth.yaml` — *not* under `checks:` (the harness fans
out every `checks.*` key as a job; a top-level block is invisible to it and read
only by this module):

```yaml
rust-build:
  app: xelis_daemon            # ARG app = the cargo BIN target (`--bin $app`)
  binary: xelis_daemon         # artifact filename under target/release
  dockerfile: Dockerfile
  target: builder              # stage that holds target/release/<binary> (needs a shell)
  artifact_path: /tmp/xelis-build/target/release/xelis_daemon
  publish: ""                  # optional staging repo, e.g. zot.viporlab.net/demo/x-staging
  scan:
    enabled: false
    fail_on: high,critical
    ignore_unfixed: true
    sbom_repo: ""
```

Defaults apply when the block is absent: `app=xelis_daemon`, `target=builder`,
`artifact_path=/tmp/xelis-build/target/release/xelis_daemon`, no publish, no scan.

## Lessons baked in

- `ARG app` must be the **bin name**, not the short directory name: cargo-chef
  runs `--bin $app` and fails with *"No workspace package or binary target
  named 'daemon'"* for a workspace whose bins are `xelis_daemon` / `xelis_miner`
  / `xelis_wallet`.
- The gate probes the **builder** stage, not the final distroless image —
  distroless has no shell, so an exec-based ELF-magic probe cannot run there.
- `rust:*-slim` ships no clippy/rustfmt; `lint`/`format` add the components via
  `rustup component add` in their own layer (cached after the first run).
- Artifact magic is probed with `head -c 4 … | od` rather than
  `file.contents()` — binaries exceed Dagger's 128 MiB contents limit.
