from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EvalExpectation:
    intent: str
    should_handoff: bool
    tool_names: list[str]


@dataclass
class EvalCase:
    case_id: str
    language: str
    transcript: list[str]
    expected: EvalExpectation


def load_eval_cases(path: Path) -> list[EvalCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    for item in raw or []:
        expected = item.get("expected") or {}
        cases.append(
            EvalCase(
                case_id=str(item.get("id") or "").strip(),
                language=str(item.get("language") or "").strip(),
                transcript=[str(line or "") for line in (item.get("transcript") or [])],
                expected=EvalExpectation(
                    intent=str(expected.get("intent") or "").strip(),
                    should_handoff=bool(expected.get("should_handoff")),
                    tool_names=[str(name or "").strip() for name in (expected.get("tool_names") or []) if str(name or "").strip()],
                ),
            )
        )
    return cases


def score_results(cases: list[EvalCase], outputs: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(item.get("case_id") or item.get("id") or "").strip(): item for item in outputs or []}
    scored_cases: list[dict[str, Any]] = []
    for case in cases:
        actual = by_id.get(case.case_id) or {}
        actual_tools = {str(name or "").strip() for name in (actual.get("tool_names") or []) if str(name or "").strip()}
        expected_tools = set(case.expected.tool_names)
        intent_ok = str(actual.get("intent") or "").strip() == case.expected.intent
        handoff_ok = bool(actual.get("should_handoff")) == case.expected.should_handoff
        tools_ok = expected_tools.issubset(actual_tools)
        scored_cases.append(
            {
                "case_id": case.case_id,
                "intent_ok": intent_ok,
                "handoff_ok": handoff_ok,
                "tools_ok": tools_ok,
                "expected_intent": case.expected.intent,
                "actual_intent": actual.get("intent"),
                "expected_handoff": case.expected.should_handoff,
                "actual_handoff": actual.get("should_handoff"),
                "expected_tools": sorted(expected_tools),
                "actual_tools": sorted(actual_tools),
                "passed": intent_ok and handoff_ok and tools_ok,
            }
        )
    passed = sum(1 for item in scored_cases if item["passed"])
    total = len(scored_cases)
    return {
        "summary": {
            "total_cases": total,
            "passed_cases": passed,
            "pass_rate": round((passed / total), 4) if total else 0.0,
        },
        "cases": scored_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score AI replay/eval results against expected Moroccan customer service cases.")
    parser.add_argument(
        "--cases",
        default=str(Path(__file__).with_name("eval_cases.json")),
        help="Path to eval case fixture JSON.",
    )
    parser.add_argument(
        "--outputs",
        required=True,
        help="Path to model output JSON. Expected shape: [{case_id, intent, should_handoff, tool_names: []}, ...]",
    )
    args = parser.parse_args()

    cases = load_eval_cases(Path(args.cases))
    outputs = json.loads(Path(args.outputs).read_text(encoding="utf-8"))
    report = score_results(cases, outputs if isinstance(outputs, list) else [])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
