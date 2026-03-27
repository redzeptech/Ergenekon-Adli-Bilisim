"""Simple Sigma-like matching rules for Amcache records."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

SigmaData = dict[str, dict[str, dict[str, Any]]]
Rule = dict[str, Any]

DEFAULT_SIGMA_RULES: list[Rule] = [
    {
        "id": "proc_creation_win_susp_folders",
        "description": "Supheli dizinden (Temp/Recycle) calisan dosyalar",
        "condition": r".*\\(Temp|Recycle\.bin|AppData\\Local\\Temp)\\.*\.exe",
        "level": "high",
    },
    {
        "id": "proc_creation_win_double_extension",
        "description": "Cift uzantili supheli dosya (orn: fatura.pdf.exe)",
        "condition": r".*\.[a-z0-9]{2,4}\.exe$",
        "level": "critical",
    },
    {
        "id": "proc_creation_win_hex_filename",
        "description": "Sadece rastgele karakterlerden olusan dosya adi",
        "condition": r".*\\([a-f0-9]{8,})\.exe$",
        "level": "medium",
    },
]


def load_sigma_rules(rules_path: Path | str | None = None) -> list[Rule]:
    """Load Sigma-like rules from YAML file or fallback defaults.

    Args:
        rules_path: Optional YAML file path.

    Returns:
        Rule list.
    """
    if not rules_path:
        return DEFAULT_SIGMA_RULES

    path = Path(rules_path)
    if not path.exists():
        return DEFAULT_SIGMA_RULES

    with path.open("r", encoding="utf-8") as file_obj:
        raw = yaml.safe_load(file_obj) or {}
    rule_rows = raw.get("rules", [])
    loaded: list[Rule] = []
    for row in rule_rows:
        if not isinstance(row, dict):
            continue
        # Backward-compatible lightweight rule format.
        if all(key in row for key in ("id", "description", "condition", "level")):
            loaded.append(
                {
                    "id": str(row["id"]),
                    "description": str(row["description"]),
                    "condition": str(row["condition"]),
                    "level": str(row["level"]).lower(),
                }
            )
            continue

        # SigmaHQ-like rule format (partial support).
        # Example keys: title, id, level, detection.selection, detection.condition
        if "detection" in row and isinstance(row["detection"], dict):
            converted = _convert_sigmahq_rule(row)
            if converted:
                loaded.append(converted)
    return loaded or DEFAULT_SIGMA_RULES


def _severity_rank(level: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(level.lower(), 0)


def _record_alert(vals: dict[str, Any], rule: Rule, alerts: list[dict[str, Any]]) -> None:
    """Write normalized Sigma alert fields to record and global alert list."""
    prior_level = str(vals.get("SigmaLevel", ""))
    if _severity_rank(rule["level"]) >= _severity_rank(prior_level):
        vals["SigmaRuleId"] = rule["id"]
        vals["SigmaAlert"] = rule["description"]
        vals["SigmaLevel"] = rule["level"]
    alerts.append(dict(vals))


def _sigmahq_field_to_rule(field: str, value: str) -> Rule | None:
    """Convert supported SigmaHQ field selectors to internal matcher rule."""
    mapping = {
        "FilePath|re": ("FilePath", "re"),
        "FilePath|contains": ("FilePath", "contains"),
        "FilePath|endswith": ("FilePath", "endswith"),
        "OriginalFileName|re": ("OriginalFileName", "re"),
        "Name|re": ("Name", "re"),
    }
    if field not in mapping:
        return None
    target_field, op = mapping[field]
    return {"field": target_field, "op": op, "value": value}


def _convert_sigmahq_rule(raw_rule: dict[str, Any]) -> Rule | None:
    """Convert partial SigmaHQ rule into internal format.

    Supported shape:
    - detection.selection*: { "FilePath|re": "...", ... }
    - detection.condition: "selection1 or selection2" (also supports "and")
    """
    detection = raw_rule.get("detection")
    if not isinstance(detection, dict):
        return None
    condition = str(detection.get("condition", "")).strip().lower()
    if not condition:
        return None
    selection_tests: dict[str, list[Rule]] = {}
    for key, selection in detection.items():
        if key == "condition" or not str(key).startswith("selection"):
            continue
        if not isinstance(selection, dict):
            continue
        tests: list[Rule] = []
        for sigma_field, sigma_value in selection.items():
            if not isinstance(sigma_value, str):
                continue
            matcher = _sigmahq_field_to_rule(str(sigma_field), sigma_value)
            if matcher:
                tests.append(matcher)
        if tests:
            selection_tests[str(key).lower()] = tests
    if not selection_tests:
        return None

    normalized_condition = _normalize_sigma_condition(condition, selection_tests)
    logic_tokens = re.findall(
        r"(selection[0-9a-z_]*|and|or|not|\(|\))",
        normalized_condition,
    )
    if not logic_tokens:
        return None
    return {
        "id": str(raw_rule.get("id", "sigmahq_rule")),
        "description": str(raw_rule.get("title", "SigmaHQ rule match")),
        "level": str(raw_rule.get("level", "medium")).lower(),
        "kind": "sigmahq",
        "logic": logic_tokens,
        "selections": selection_tests,
    }


def _normalize_sigma_condition(condition: str, selection_tests: dict[str, list[Rule]]) -> str:
    """Expand Sigma shorthands like '1 of selection*' and 'all of selection*'."""
    condition_norm = condition.lower().strip()
    selection_keys = sorted(selection_tests.keys())
    if not selection_keys:
        return condition_norm

    def _replacement(match: re.Match[str]) -> str:
        quantifier = match.group(1).lower()
        prefix = match.group(2).lower()
        matched = [key for key in selection_keys if key.startswith(prefix)]
        if not matched:
            return ""
        joiner = " or " if quantifier == "1" else " and "
        return "(" + joiner.join(matched) + ")"

    # Supports expressions such as:
    # 1 of selection*
    # all of selection*
    # 1 of selection_*
    pattern = re.compile(r"\b(1|all)\s+of\s+(selection[0-9a-z_]*)\*\b")
    return pattern.sub(_replacement, condition_norm)


def _match_rule(rule: Rule, vals: dict[str, Any]) -> bool:
    """Evaluate one rule against a single record."""
    if rule.get("kind") == "sigmahq":
        return _match_sigmahq_rule(rule, vals)

    if "condition" in rule:
        path = str(vals.get("FilePath", ""))
        return bool(re.match(rule["condition"], path, re.IGNORECASE))

    field = rule.get("field", "FilePath")
    op = rule.get("op", "re")
    value = rule.get("value", "")
    source = str(vals.get(field, ""))
    if op == "re":
        return bool(re.search(value, source, re.IGNORECASE))
    if op == "contains":
        return value.lower() in source.lower()
    if op == "endswith":
        return source.lower().endswith(value.lower())
    return False


def _match_selection(tests: list[Rule], vals: dict[str, Any]) -> bool:
    """All field checks in one selection must match."""
    return all(_match_rule(test, vals) for test in tests)


def _match_sigmahq_rule(rule: Rule, vals: dict[str, Any]) -> bool:
    """Evaluate SigmaHQ logic tokens with and/or and parentheses."""
    tokens: list[str] = list(rule.get("logic", []))
    selections: dict[str, list[Rule]] = dict(rule.get("selections", {}))
    if not tokens:
        return False

    def selection_value(token: str) -> bool:
        return _match_selection(selections.get(token, []), vals)

    output_queue: list[str] = []
    op_stack: list[str] = []
    precedence = {"or": 1, "and": 2, "not": 3}

    for token in tokens:
        if token.startswith("selection"):
            output_queue.append(token)
            continue
        if token in {"and", "or", "not"}:
            while op_stack and op_stack[-1] in precedence and precedence[op_stack[-1]] >= precedence[token]:
                output_queue.append(op_stack.pop())
            op_stack.append(token)
            continue
        if token == "(":
            op_stack.append(token)
            continue
        if token == ")":
            while op_stack and op_stack[-1] != "(":
                output_queue.append(op_stack.pop())
            if op_stack and op_stack[-1] == "(":
                op_stack.pop()
            continue

    while op_stack:
        top = op_stack.pop()
        if top != "(":
            output_queue.append(top)

    eval_stack: list[bool] = []
    for token in output_queue:
        if token.startswith("selection"):
            eval_stack.append(selection_value(token))
            continue
        if token == "not" and len(eval_stack) >= 1:
            eval_stack.append(not eval_stack.pop())
            continue
        if token in {"and", "or"} and len(eval_stack) >= 2:
            rhs = eval_stack.pop()
            lhs = eval_stack.pop()
            eval_stack.append(lhs and rhs if token == "and" else lhs or rhs)

    return bool(eval_stack[-1]) if eval_stack else False


def _check_masquerading(vals: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
    """Flag records where Name and OriginalFileName do not match."""
    name = str(vals.get("Name", "")).strip().lower()
    original = str(vals.get("OriginalFileName", "")).strip().lower()
    name_base = Path(name).name
    orig_base = Path(original).name
    if name_base and orig_base and name_base != orig_base:
        _record_alert(
            vals,
            {
                "id": "proc_creation_win_potential_masquerading_name_mismatch",
                "description": "CRITICAL - Potential Masquerading",
                "condition": "name != original_file_name",
                "level": "critical",
            },
            alerts,
        )


def apply_sigma_rules(
    data: SigmaData, rules_path: Path | str | None = None
) -> tuple[SigmaData, list[dict[str, Any]]]:
    """Apply Sigma-like rules and masquerading checks on Amcache records.

    Args:
        data: Category -> record name -> field map.
        rules_path: Optional YAML file path for external rules.

    Returns:
        Tuple of (mutated data, matched alert rows).
    """
    rules = load_sigma_rules(rules_path)
    alerts: list[dict[str, Any]] = []
    for _, recs in data.items():
        for _, vals in recs.items():
            for rule in rules:
                if _match_rule(rule, vals):
                    _record_alert(vals, rule, alerts)
            _check_masquerading(vals, alerts)
    return data, alerts
