"""CI proof arm (review P6): the pipeline must actually RUN the parity
batteries, not skip 54 percent of the suite and still report green.

This is a text assertion over the committed workflow: it cannot prove
GitHub ran it, but it does prove the two mechanisms the review demanded
exist in the tree — the sibling checkout with GROUPWARE_PATH, and a step
that FAILS the build when tests skip.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

_CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def test_ci_checks_out_the_sibling_broker():
    text = _CI.read_text()
    assert "sibling broker" in text
    assert "groupwareAccessBroker" in text
    assert "vars.GROUPWARE_REPO" in text  # owner-settable, private-repo path


def test_ci_sets_groupware_path_for_the_test_run():
    text = _CI.read_text()
    assert "GROUPWARE_PATH:" in text
    assert ".siblings/groupwareAccessBroker" in text


def test_ci_fails_when_parity_batteries_skip():
    text = _CI.read_text()
    assert "Parity batteries must RUN" in text
    assert "skipped" in text
    assert "exit 1" in text


def test_ci_has_one_coverage_gate_not_two():
    """The old workflow ran pytest twice and the second invocation's
    failure was masked by `2>/dev/null || coverage report` — the gate
    must be one run with --cov-fail-under in the same command."""
    text = _CI.read_text()
    assert text.count("--cov-fail-under=100") == 1
    assert "2>/dev/null" not in text
