#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "autoreview"


def load_helper() -> dict[str, object]:
    return runpy.run_path(str(SCRIPT), run_name="autoreview_under_test")


def git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Autoreview Test",
            "GIT_AUTHOR_EMAIL": "autoreview@example.invalid",
            "GIT_COMMITTER_NAME": "Autoreview Test",
            "GIT_COMMITTER_EMAIL": "autoreview@example.invalid",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def init_repo(tempdir: Path) -> Path:
    repo = tempdir / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Autoreview Test")
    git(repo, "config", "user.email", "autoreview@example.invalid")
    return repo


class AutoreviewHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def resolved_reviewer(self, **overrides: object) -> argparse.Namespace:
        reviewer = self.helper["reviewer_args"](self.helper["reviewer_test_args"](**overrides))[0]
        defaults = {
            "codex_bin": "codex",
            "claude_bin": "claude",
            "droid_bin": "droid",
            "copilot_bin": "copilot",
            "opencode_bin": "opencode",
            "pi_bin": "pi",
            "tools": True,
            "web_search": False,
            "stream_engine_output": False,
            "claude_allowed_tools": "Read,Grep,Glob,WebSearch,WebFetch",
        }
        for key, value in defaults.items():
            setattr(reviewer, key, value)
        return reviewer

    def capture_engine_commands(self) -> list[list[str]]:
        captured: list[list[str]] = []

        def fake_run_with_heartbeat(
            cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, '{"findings":[]}', "")

        for name in (
            "run_codex",
            "run_claude",
            "run_droid",
            "run_copilot",
            "run_opencode",
            "run_pi",
        ):
            self.helper[name].__globals__["run_with_heartbeat"] = fake_run_with_heartbeat
            self.helper[name].__globals__["resolve_command"] = (
                lambda command, repo: f"/resolved/{command}"
            )
        self.helper["run_claude"].__globals__["ensure_claude_isolation_supported"] = (
            lambda args, repo: None
        )
        self.helper["run_pi"].__globals__["ensure_pi_isolation_supported"] = (
            lambda args, repo: f"/resolved/{args.pi_bin}"
        )
        return captured

    def test_local_bundle_blocks_sensitive_untracked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / ".env").write_text("placeholder=true\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "untracked sensitive files"):
                self.helper["local_bundle"](repo)

    def test_local_bundle_omits_safe_untracked_binary_content(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "image.bin").write_bytes(b"\x89PNG\r\n\0binary-content")

            bundle = self.helper["local_bundle"](repo)

            self.assertIn("## image.bin\n[binary file omitted]", bundle)

    def test_branch_bundle_rejects_unsafe_or_unknown_base_before_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")

            with self.assertRaisesRegex(SystemExit, "unsafe base ref"):
                self.helper["branch_bundle"](repo, "--help")
            with self.assertRaisesRegex(SystemExit, "unknown base ref"):
                self.helper["branch_bundle"](repo, "origin/main")

    def test_git_path_list_preserves_newline_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            rel = "line\nbreak.txt"
            (repo / rel).write_text("content\n", encoding="utf-8")
            git(repo, "add", rel)

            paths = self.helper["git_path_list"](repo, "ls-files", "-z")

            self.assertIn(rel, paths)

    def test_bounded_truncates_large_bundle_component(self) -> None:
        bounded = self.helper["bounded"]("x" * 25, 10)

        self.assertEqual(bounded, "x" * 10 + "\n\n[truncated at 10 characters]\n")

    def test_read_text_truncates_without_scanning_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "large.txt"
            path.write_bytes(b"x" * 200_000 + b"\0tail")

            text = self.helper["read_text"](path)

            self.assertIn("[truncated at 180000 characters]", text)
            self.assertNotEqual(text, "[binary file omitted]")

    def test_evidence_file_must_be_repo_relative_and_not_symlinked(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            outside = root / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "repo-relative"):
                self.helper["validate_evidence_file"](repo, str(outside), "--prompt-file")

            target = repo / "notes.md"
            target.write_text("notes\n", encoding="utf-8")
            link = repo / "link.md"
            link.symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "symlinked"):
                self.helper["validate_evidence_file"](repo, "link.md", "--dataset")

    def test_safe_engine_env_strips_process_injection_variables(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["GIT_DIR"] = "/tmp/unsafe-git-dir"
                os.environ["GIT_CONFIG_COUNT"] = "99"
                os.environ["DYLD_INSERT_LIBRARIES"] = "/tmp/unsafe.dylib"
                os.environ["NODE_OPTIONS"] = "--require=/tmp/unsafe.js"

                env = self.helper["safe_engine_env"](repo)

                self.assertNotEqual(env.get("GIT_DIR"), "/tmp/unsafe-git-dir")
                self.assertEqual(
                    env["GIT_CONFIG_COUNT"],
                    str(len(self.helper["ENGINE_GIT_CONFIG_OVERRIDES"])),
                )
                self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
                self.assertNotIn("NODE_OPTIONS", env)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_safe_engine_env_excludes_repo_local_path_entries(self) -> None:
        old_path = os.environ.get("PATH", "")
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            os.environ["PATH"] = f"{repo}{os.pathsep}{old_path}"
            try:
                env = self.helper["safe_engine_env"](repo)
            finally:
                os.environ["PATH"] = old_path

            self.assertNotIn(str(repo.resolve()), env["PATH"].split(os.pathsep))

    def test_large_repo_relative_evidence_file_is_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            evidence = repo / "evidence.txt"
            evidence.write_text("x" * 600_000, encoding="utf-8")

            _, content = self.helper["validate_evidence_file"](repo, "evidence.txt", "--dataset")

            self.assertIn("[truncated at 180000 characters]", content)

    def test_copilot_allows_web_fetch_only_when_web_search_is_enabled(self) -> None:
        captured: list[list[str]] = []

        def fake_run_with_heartbeat(
            cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, '{"findings":[]}', "")

        self.helper["run_copilot"].__globals__["run_with_heartbeat"] = fake_run_with_heartbeat
        self.helper["run_copilot"].__globals__["resolve_command"] = (
            lambda command, repo: f"/resolved/{command}"
        )
        args = argparse.Namespace(
            copilot_bin="copilot",
            thinking=None,
            tools=True,
            model=None,
            web_search=False,
            stream_engine_output=False,
        )

        self.helper["run_copilot"](args, Path("/repo"), "prompt")

        self.assertNotIn("--allow-tool=web_fetch", captured[-1])
        self.assertFalse(any(arg == "--allow-all-urls" for arg in captured[-1]))

        args.web_search = True
        self.helper["run_copilot"](args, Path("/repo"), "prompt")

        self.assertIn("--allow-tool=web_fetch", captured[-1])
        self.assertIn("--allow-all-urls", captured[-1])

    def test_fast_profile_preserves_explicit_precedence(self) -> None:
        old = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update(
                {
                    "AUTOREVIEW_FAST": "1",
                    "AUTOREVIEW_CODEX_FAST_MODEL": "env-fast-codex",
                    "AUTOREVIEW_FAST_THINKING": "medium",
                    "AUTOREVIEW_CODEX_MODEL": "env-codex",
                    "AUTOREVIEW_CODEX_THINKING": "high",
                }
            )

            reviewer = self.helper["reviewer_args"](
                self.helper["reviewer_test_args"](
                    reviewers="codex:inline-codex:minimal",
                    model=["codex=cli-codex"],
                    thinking=["codex=low"],
                )
            )[0]

            self.assertTrue(reviewer.fast_enabled)
            self.assertEqual(reviewer.model, "inline-codex")
            self.assertEqual(reviewer.thinking, "minimal")
            self.assertEqual(reviewer.model_source, "inline")
            self.assertEqual(reviewer.thinking_source, "inline")
            self.assertIsNone(reviewer.fast_model_source)
            self.assertIsNone(reviewer.fast_thinking_source)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_fast_profile_applies_gap_defaults_and_skips_copilot_thinking(self) -> None:
        reviewers = self.helper["reviewer_args"](
            self.helper["reviewer_test_args"](
                reviewers="codex,copilot",
                fast=True,
                fast_model=["codex=fast-codex"],
            )
        )
        codex = next(reviewer for reviewer in reviewers if reviewer.engine == "codex")
        copilot = next(reviewer for reviewer in reviewers if reviewer.engine == "copilot")

        self.assertEqual(codex.model, "fast-codex")
        self.assertEqual(codex.thinking, self.helper["DEFAULT_FAST_THINKING"])
        self.assertEqual(codex.fast_model_source, "fast-cli-engine")
        self.assertEqual(codex.fast_thinking_source, "fast-default")
        self.assertIsNone(copilot.thinking)
        self.assertIsNone(copilot.fast_thinking_source)
        self.assertFalse(copilot.provider_fast_requested)

    def test_fast_profile_thinking_only_ignores_fast_model_aliases(self) -> None:
        reviewer = self.helper["reviewer_args"](
            self.helper["reviewer_test_args"](
                engine="droid",
                fast=True,
                fast_strategy="thinking-only",
                fast_model=["droid=claude-opus-4-8-fast"],
            )
        )[0]

        self.assertIsNone(reviewer.model)
        self.assertEqual(reviewer.thinking, self.helper["DEFAULT_FAST_THINKING"])
        self.assertEqual(reviewer.thinking_source, "fast-default")
        self.assertIsNone(reviewer.fast_model_source)
        self.assertFalse(reviewer.provider_fast_requested)

    def test_fast_profile_rejects_unsupported_engine_specific_thinking(self) -> None:
        with self.assertRaisesRegex(SystemExit, "not supported for copilot"):
            self.helper["reviewer_args"](
                self.helper["reviewer_test_args"](
                    engine="copilot",
                    fast=True,
                    fast_thinking=["copilot=low"],
                )
            )

    def test_fast_provider_wiring_adds_codex_per_run_config_only_when_allowed(self) -> None:
        captured = self.capture_engine_commands()
        repo = Path("/repo")

        fast = self.resolved_reviewer(engine="codex", fast=True)
        self.helper["run_codex"](fast, repo, "prompt")
        self.assertIn('service_tier="fast"', captured[-1])
        self.assertIn('model_reasoning_effort="low"', captured[-1])
        self.assertLess(captured[-1].index('service_tier="fast"'), captured[-1].index("exec"))

        captured.clear()
        thinking_only = self.resolved_reviewer(
            engine="codex",
            fast=True,
            fast_strategy="thinking-only",
        )
        self.helper["run_codex"](thinking_only, repo, "prompt")
        self.assertNotIn('service_tier="fast"', captured[-1])
        self.assertIn('model_reasoning_effort="low"', captured[-1])

    def test_fast_provider_wiring_uses_existing_effort_knobs_for_non_codex_engines(self) -> None:
        captured = self.capture_engine_commands()
        repo = Path("/repo")

        claude = self.resolved_reviewer(engine="claude", fast=True)
        self.helper["run_claude"](claude, repo, "prompt")
        self.assertIn("--effort", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--effort") + 1], "low")
        self.assertFalse(any("fastMode" in arg or "fast_mode" in arg for arg in captured[-1]))

        droid = self.resolved_reviewer(
            engine="droid",
            fast=True,
            fast_model=["droid=claude-opus-4-8-fast"],
        )
        self.helper["run_droid"](droid, repo, "prompt")
        self.assertIn("--model", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--model") + 1], "claude-opus-4-8-fast")
        self.assertIn("-r", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("-r") + 1], "low")

        opencode = self.resolved_reviewer(
            engine="opencode",
            fast=True,
            fast_model=["opencode=github-copilot/gpt-5.4"],
        )
        self.helper["run_opencode"](opencode, repo, "prompt")
        self.assertIn("-m", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("-m") + 1], "github-copilot/gpt-5.4")
        self.assertIn("--variant", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--variant") + 1], "low")

        pi = self.resolved_reviewer(
            engine="pi",
            fast=True,
            fast_model=["pi=openai/gpt-5.5"],
        )
        self.helper["run_pi"](pi, repo, "prompt")
        self.assertIn("--model", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--model") + 1], "openai/gpt-5.5")
        self.assertIn("--thinking", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--thinking") + 1], "low")

    def test_fast_provider_wiring_keeps_copilot_model_only(self) -> None:
        captured = self.capture_engine_commands()
        repo = Path("/repo")
        copilot = self.resolved_reviewer(
            engine="copilot",
            fast=True,
            fast_model=["copilot=gpt-5.2"],
        )

        self.helper["run_copilot"](copilot, repo, "prompt")

        self.assertIn("--model", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--model") + 1], "gpt-5.2")
        self.assertNotIn("--effort", captured[-1])
        self.assertNotIn("--reasoning-effort", captured[-1])
        self.assertNotIn("--thinking", captured[-1])


if __name__ == "__main__":
    unittest.main()
