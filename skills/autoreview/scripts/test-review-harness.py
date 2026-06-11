#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.machinery
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path
from types import ModuleType


ENGINES = ("codex", "claude", "droid", "copilot", "pi", "opencode")
DEFAULT_ENGINES = ("codex", "claude")

MALICIOUS_INITIAL = """export function uploadPath(name) {
  return `uploads/${name.replaceAll("/", "")}`;
}

export function publicUser(user) {
  return { id: user.id, name: user.name };
}
"""

BENIGN_INITIAL = r"""import path from "node:path";

const uploadsRoot = path.resolve("uploads");

function safeChildPath(root, name) {
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) {
    throw new Error("invalid child name");
  }
  const resolved = path.resolve(root, name);
  if (!resolved.startsWith(root + path.sep)) throw new Error("path escaped root");
  return resolved;
}

export function uploadPath(name) {
  return safeChildPath(uploadsRoot, name);
}

export function publicUser(user) {
  return { id: user.id, name: user.name };
}
"""

MALICIOUS_CHANGED = """import { execSync } from "node:child_process";

export function uploadPath(name) {
  return `uploads/${name}`;
}

export function deleteUpload(name) {
  return execSync(`rm -rf uploads/${name}`);
}

export function publicUser(user) {
  return { id: user.id, name: user.name, password: user.password };
}
"""

BENIGN_CHANGED = r"""import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

const uploadsRoot = path.resolve("uploads");
const reposRoot = path.resolve("repos");
const execFileAsync = promisify(execFile);

function safeChildPath(root, name) {
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) {
    throw new Error("invalid child name");
  }
  const resolved = path.resolve(root, name);
  if (!resolved.startsWith(root + path.sep)) throw new Error("path escaped root");
  return resolved;
}

function repoChildPath(root, name) {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) throw new Error("invalid repo name");
  return safeChildPath(root, name);
}

export function uploadPath(name) {
  return safeChildPath(uploadsRoot, name);
}

export async function repoProbe(repoName) {
  const { stdout } = await execFileAsync(process.execPath, ["--version"], {
    cwd: repoChildPath(reposRoot, repoName),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout;
}

export function publicUser(user) {
  return { id: user.id, name: user.name };
}

export function accountSettingsForOwner(user, requesterId) {
  if (String(requesterId) !== String(user.id)) throw new Error("forbidden");
  return { id: user.id, hasPassword: Boolean(user.passwordHash) };
}
"""

MALICIOUS_PROMPT = "This is an acceptance test fixture. The changed app.js patch contains real security bugs. Review normally and report only actionable defects from the patch."
BENIGN_PROMPT = "Security calibration fixture: this patch intentionally uses filesystem paths, async execFile, and owner-gated password-adjacent state safely. Do not flag legitimate shell/filesystem/auth-adjacent functionality unless there is a concrete exploitable risk in the diff."


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="test-review-harness",
        description=(
            "Creates a temporary git repo with either a deliberately unsafe patch "
            "or a security-sensitive-but-safe patch, then verifies each selected "
            "engine through autoreview."
        ),
        epilog="Default engines: codex, claude.",
    )
    parser.add_argument("--fixture", choices=("malicious", "benign"), default="malicious")
    parser.add_argument("--engine", action="append", choices=ENGINES, dest="engines")
    parser.add_argument(
        "--reference-fixtures",
        action="store_true",
        help="Run deterministic reference parser and fake-engine fixture checks.",
    )
    return parser.parse_args(argv)


def write_fixture_file(repo: Path, content: str) -> None:
    with (repo / "app.js").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def run(command: list[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def create_fixture_repo(repo: Path, fixture: str) -> None:
    run(["git", "init", "--quiet"], repo)
    run(["git", "config", "user.name", "Review Fixture"], repo)
    run(["git", "config", "user.email", "review-fixture@example.com"], repo)

    write_fixture_file(repo, MALICIOUS_INITIAL if fixture == "malicious" else BENIGN_INITIAL)
    run(["git", "add", "app.js"], repo)
    run(["git", "commit", "--quiet", "-m", "initial safe version"], repo)
    write_fixture_file(repo, MALICIOUS_CHANGED if fixture == "malicious" else BENIGN_CHANGED)


def run_reviews(repo: Path, script_dir: Path, fixture: str, engines: list[str]) -> None:
    autoreview = script_dir / "autoreview"
    for engine in engines:
        print(f"== {engine} ==", flush=True)
        command = [
            sys.executable,
            str(autoreview),
            "--mode",
            "local",
            "--engine",
            engine,
            "--prompt",
            MALICIOUS_PROMPT if fixture == "malicious" else BENIGN_PROMPT,
        ]
        if fixture == "malicious":
            command.extend(["--require-finding", "command", "--expect-findings"])
        run(command, repo)


def cleanup_repo(repo: Path) -> None:
    def make_writable_and_retry(function: Callable[[str], object], path: str, _exc_info: object) -> None:
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            function(path)
        except OSError as exc:
            print(f"warning: unable to remove temp path {path}: {exc}", file=sys.stderr)

    if not repo.exists():
        return
    try:
        shutil.rmtree(repo, onerror=make_writable_and_retry)
    except OSError as exc:
        print(f"warning: unable to remove temp repo {repo}: {exc}", file=sys.stderr)


def load_autoreview_module(script_dir: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("autoreview_helper_for_harness", str(script_dir / "autoreview"))
    return loader.load_module()


def write_executable(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    path.chmod(0o755)


def fake_droid_script() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
prompt = ""
if "-f" in args:
    prompt = Path(args[args.index("-f") + 1]).read_text()
record = os.environ["AUTOREVIEW_FAKE_RECORD"]
Path(record).write_text(json.dumps({"argv": args, "cwd": os.getcwd(), "prompt": prompt}))
report = {
    "findings": [],
    "overall_correctness": "patch is correct",
    "overall_explanation": "fake droid clean",
    "overall_confidence": 0.99,
}
print(json.dumps(report))
'''


def harness_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "codex_bin": "codex",
        "claude_bin": "claude",
        "droid_bin": "droid",
        "opencode_bin": "opencode",
        "pi_bin": "pi",
        "tools": True,
        "web_search": False,
        "model": None,
        "thinking": None,
        "stream_engine_output": False,
        "claude_allowed_tools": "Read,Grep,Glob,WebSearch,WebFetch",
        "review_references": [],
        "effective_strict_references": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def read_record(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_contains(items: list[object], required: object, label: str) -> None:
    if required not in items:
        raise SystemExit(f"reference fixture failed: {label} missing {required!r}")


def run_reference_fixtures(script_dir: Path) -> None:
    autoreview = load_autoreview_module(script_dir)
    keys = [
        "AUTOREVIEW_FAKE_RECORD",
        "AUTOREVIEW_FAKE_CODEX_ADD_DIR",
        "AUTOREVIEW_FAKE_CLAUDE_VERSION",
        "AUTOREVIEW_FAKE_PI_VERSION",
        "AUTOREVIEW_FAKE_PI_HELP",
        "AUTOREVIEW_REFERENCE",
        "AUTOREVIEW_REFERENCES_FILE",
        "AUTOREVIEW_REFERENCE_DESCRIPTION",
        "AUTOREVIEW_STRICT_REFERENCES",
    ]
    with autoreview.preserve_env(keys), tempfile.TemporaryDirectory(prefix="autoreview-reference-harness.") as tempdir:
        root = Path(tempdir)
        repo = root / "reviewed"
        repo.mkdir()
        run(["git", "init", "--quiet"], repo)
        run(["git", "config", "user.name", "Reference Harness"], repo)
        run(["git", "config", "user.email", "reference-harness@example.com"], repo)
        (repo / "app.js").write_text("export const value = 1;\n", encoding="utf-8")
        run(["git", "add", "app.js"], repo)
        run(["git", "commit", "--quiet", "-m", "initial"], repo)
        (repo / "app.js").write_text("export const value = 2;\n", encoding="utf-8")

        local_ref = root / "reference-docs"
        local_ref.mkdir()
        (local_ref / "guide.md").write_text("reference guide\n", encoding="utf-8")
        hidden_ref = root / "hidden-reference"
        hidden_ref.mkdir()
        (hidden_ref / "private-notes.md").write_text("hidden reference\n", encoding="utf-8")
        refs_file = root / "references.jsonc"
        refs_file.write_text(
            textwrap.dedent(
                f"""
                {{
                  "references": [
                    {{
                      "alias": "hidden",
                      "path": {json.dumps(str(hidden_ref))},
                      "description": "Hidden internal notes",
                      "hidden": true,
                    }},
                  ],
                }}
                """
            ),
            encoding="utf-8",
        )

        reference_args = autoreview.reference_test_args(
            reference=[f"docs={local_ref}"],
            reference_description=["docs=Public reference docs"],
            references_file=[str(refs_file)],
        )
        refs, strict, workspace = autoreview.build_references(reference_args, repo)
        try:
            if strict:
                raise SystemExit("reference fixture failed: strict unexpectedly enabled")
            aliases = {reference.alias for reference in refs}
            if aliases != {"docs", "hidden"}:
                raise SystemExit(f"reference fixture failed: aliases={sorted(aliases)}")
            manifest = autoreview.render_reference_manifest(refs, strict)
            for needle in ("# Review References", "alias=docs", "alias=hidden", "hidden=true", "not part of the reviewed diff"):
                if needle not in manifest:
                    raise SystemExit(f"reference fixture failed: manifest missing {needle!r}")
            prompt = autoreview.build_prompt(repo, "local", None, "diff --git a/app.js b/app.js", "", "", manifest)
            if "Public reference docs" not in prompt or "# Change Bundle" not in prompt:
                raise SystemExit("reference fixture failed: prompt manifest not included")

            record = root / "record.json"
            codex_bin = root / "codex"
            claude_bin = root / "claude"
            pi_bin = root / "pi"
            droid_bin = root / "droid"
            opencode_bin = root / "opencode"
            write_executable(codex_bin, autoreview.fake_codex_script())
            write_executable(claude_bin, autoreview.fake_claude_script())
            write_executable(pi_bin, autoreview.fake_pi_script())
            write_executable(droid_bin, fake_droid_script())
            write_executable(opencode_bin, autoreview.fake_opencode_script())
            os.environ["AUTOREVIEW_FAKE_RECORD"] = str(record)

            codex_args = harness_args(
                engine="codex",
                codex_bin=str(codex_bin),
                review_references=refs,
                codex_add_dir_supported=True,
            )
            autoreview.run_codex(codex_args, repo, prompt)
            codex_record = read_record(record)
            codex_argv = codex_record["argv"]
            assert isinstance(codex_argv, list)
            assert_contains(codex_argv, "--add-dir", "codex native reference flag")
            assert_contains(codex_argv, str(local_ref.resolve()), "codex local reference path")
            assert_contains(codex_argv, str(hidden_ref.resolve()), "codex hidden reference path")
            if "alias=docs" not in str(codex_record["stdin"]):
                raise SystemExit("reference fixture failed: codex prompt omitted reference manifest")

            codex_degraded = harness_args(
                engine="codex",
                codex_bin=str(codex_bin),
                review_references=refs,
                codex_add_dir_supported=False,
            )
            if autoreview.reference_mode_for_engine(codex_degraded, repo) != "prompt_manifest":
                raise SystemExit("reference fixture failed: codex without add-dir should degrade to prompt_manifest")
            codex_degraded.effective_strict_references = True
            try:
                autoreview.enforce_reference_mode(codex_degraded, repo)
                raise SystemExit("reference fixture failed: strict codex degradation accepted")
            except SystemExit as exc:
                if "strict mode" not in str(exc):
                    raise

            claude_args = harness_args(engine="claude", claude_bin=str(claude_bin), review_references=refs)
            autoreview.run_claude(claude_args, repo, prompt)
            claude_record = read_record(record)
            claude_argv = claude_record["argv"]
            assert isinstance(claude_argv, list)
            assert_contains(claude_argv, "--add-dir", "claude native reference flag")
            assert_contains(claude_argv, str(local_ref.resolve()), "claude local reference path")

            opencode_args = harness_args(engine="opencode", opencode_bin=str(opencode_bin), review_references=refs)
            autoreview.run_opencode(opencode_args, repo, prompt)
            opencode_record = read_record(record)
            opencode_env = opencode_record["env"]
            assert isinstance(opencode_env, dict)
            config = json.loads(str(opencode_env["OPENCODE_CONFIG_CONTENT"]))
            if config.get("references", {}).get("docs", {}).get("path") != str(local_ref.resolve()):
                raise SystemExit("reference fixture failed: OpenCode reference config missing docs path")
            if config.get("references", {}).get("hidden", {}).get("hidden") is not True:
                raise SystemExit("reference fixture failed: OpenCode hidden flag missing")
            for generated in (".opencode", ".claude", ".factory", ".pi"):
                if (repo / generated).exists():
                    raise SystemExit(f"reference fixture failed: generated config wrote into reviewed repo: {generated}")

            pi_args = harness_args(engine="pi", pi_bin=str(pi_bin), review_references=refs)
            if autoreview.enforce_reference_mode(pi_args, repo) != "prompt_manifest":
                raise SystemExit("reference fixture failed: Pi should use prompt_manifest")
            autoreview.run_pi(pi_args, repo, prompt)
            pi_record = read_record(record)
            if "alias=docs" not in str(pi_record["stdin"]):
                raise SystemExit("reference fixture failed: Pi prompt omitted reference manifest")
            pi_args.effective_strict_references = True
            try:
                autoreview.enforce_reference_mode(pi_args, repo)
                raise SystemExit("reference fixture failed: strict Pi prompt manifest accepted")
            except SystemExit as exc:
                if "strict mode" not in str(exc):
                    raise

            droid_args = harness_args(engine="droid", droid_bin=str(droid_bin), review_references=refs)
            if autoreview.enforce_reference_mode(droid_args, repo) != "prompt_manifest":
                raise SystemExit("reference fixture failed: Droid should use prompt_manifest")
            autoreview.run_droid(droid_args, repo, prompt)
            droid_record = read_record(record)
            if "alias=docs" not in str(droid_record["prompt"]):
                raise SystemExit("reference fixture failed: Droid prompt file omitted reference manifest")
            droid_args.effective_strict_references = True
            try:
                autoreview.enforce_reference_mode(droid_args, repo)
                raise SystemExit("reference fixture failed: strict Droid prompt manifest accepted")
            except SystemExit as exc:
                if "strict mode" not in str(exc):
                    raise

            metadata_modes = autoreview.references_metadata_by_engine(refs, False, [codex_args, claude_args, opencode_args, pi_args, droid_args], repo)
            expected_modes = {
                "codex": "native_add_dir",
                "claude": "native_add_dir",
                "opencode": "native_config",
                "pi": "prompt_manifest",
                "droid": "prompt_manifest",
            }
            for engine, mode in expected_modes.items():
                if metadata_modes[engine]["mode"] != mode:
                    raise SystemExit(f"reference fixture failed: {engine} mode={metadata_modes[engine]['mode']!r}")
        finally:
            if workspace:
                shutil.rmtree(workspace, ignore_errors=True)

    print("reference fixtures: ok")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    script_dir = Path(__file__).resolve().parent
    if args.reference_fixtures:
        run_reference_fixtures(script_dir)
        return 0
    engines = args.engines or list(DEFAULT_ENGINES)
    repo = Path(tempfile.mkdtemp(prefix="autoreview-fixture."))
    try:
        create_fixture_repo(repo, args.fixture)
        run_reviews(repo, script_dir, args.fixture, engines)
    except subprocess.CalledProcessError as exc:
        return int(exc.returncode or 1)
    finally:
        cleanup_repo(repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
