# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for release publication and image promotion."""

from pathlib import Path
import re
import unittest


CI_CONFIG = Path(__file__).parents[1] / ".gitlab-ci.yml"
TOP_LEVEL_KEY = re.compile(r"^[A-Za-z0-9_.:-]+:\s*(?:#.*)?$")


def job_section(name: str) -> str:
    lines = CI_CONFIG.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if TOP_LEVEL_KEY.match(lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def configured_stages() -> list[str]:
    stages = job_section("stages")
    return re.findall(r"^  - ([a-z-]+)$", stages, re.MULTILINE)


class ReleaseSafetyContractTests(unittest.TestCase):
    def test_publication_waits_for_blocking_security_stages(self) -> None:
        publish = job_section("publish:package:ohttp-relay")
        stages = configured_stages()

        self.assertIn("  stage: deploy", publish)
        self.assertNotRegex(publish, r"(?m)^  needs:")
        self.assertIn("  dependencies:\n    - build:release", publish)
        self.assertLess(stages.index("security"), stages.index("deploy"))
        self.assertLess(stages.index("scan"), stages.index("deploy"))

    def test_historical_tags_cannot_promote_latest(self) -> None:
        promote = job_section("promote:latest")

        self.assertIn("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", promote)
        self.assertNotIn("$CI_COMMIT_TAG", promote)

    def test_main_and_tag_release_paths_are_contract_checked_in_mrs(self) -> None:
        build = job_section("build:docker")
        publish = job_section("publish:package:ohttp-relay")
        promote = job_section("promote:latest")
        contract = job_section("check:release-safety")

        for release_job in (build, publish):
            self.assertIn("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", release_job)
            self.assertIn("$CI_COMMIT_TAG =~ /^v", release_job)

        self.assertIn("- job: build:docker", promote)
        self.assertIn("- job: container_scanning", promote)
        self.assertIn("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", promote)
        self.assertIn("python3 tests/ci_release_safety.py", contract)
        self.assertIn('$CI_PIPELINE_SOURCE == "merge_request_event"', contract)
        self.assertIn("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", contract)
        self.assertIn("$CI_COMMIT_TAG =~ /^v", contract)


if __name__ == "__main__":
    unittest.main()
