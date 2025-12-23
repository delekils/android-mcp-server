from pathlib import Path

from badlog.rules import load_rules, merge_rules


def test_rule_loading_from_yaml(tmp_path: Path) -> None:
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text(
        "version: 1\nrules:\n"
        "  - name: demo\n"
        "    severity: HIGH\n"
        "    category: KERNEL\n"
        "    pattern: 'oops'\n"
        "    rationale: 'kernel oops'\n"
        "    domains: [kernel]\n"
        "    evidence:\n"
        "      - failure_class: EXECUTION_STALL\n"
        "        weight: 0.5\n"
        "        label: 'oops'\n",
        encoding="utf-8",
    )
    rules = load_rules([rule_file])
    assert len(rules) == 1
    assert rules[0].name == "demo"
    assert rules[0].rationale == "kernel oops"
    assert rules[0].regex.search("oops")


def test_merge_rules_overrides_by_name(tmp_path: Path) -> None:
    default = load_rules([Path("rules/default_rules.yaml")])
    custom_file = tmp_path / "custom.yaml"
    custom_file.write_text(
        "version: 1\nrules:\n"
        "  - name: watchdog_soft_lockup\n"
        "    severity: MEDIUM\n"
        "    category: WATCHDOG\n"
        "    pattern: 'soft lockup'\n"
        "    evidence:\n"
        "      - failure_class: EXECUTION_STALL\n"
        "        weight: 0.1\n"
        "        label: 'soft lockup'\n",
        encoding="utf-8",
    )
    custom = load_rules([custom_file])
    merged = merge_rules(default, custom)
    names = {rule.name: rule for rule in merged}
    assert names["watchdog_soft_lockup"].severity == "MEDIUM"
