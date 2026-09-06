from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from .. import settings
from ..models import ToolCallRecord, Verdict
from .tools import ToolContext, build_evidence_from_case, build_timeline_from_case

SYSTEM_PROMPT = """You are a Tier-1 SOC analyst triaging a security alert for {org}. You do first-pass investigation only: gather evidence, correlate, then produce a verdict.

Rules:
1. Be evidence-driven. Every analytical claim must reference a concrete event id or intel lookup you actually performed. Never invent log entries or reputations.
2. Use the tools to investigate before concluding: query_logs, get_user_context, get_asset_context, lookup_ip_reputation, get_mitre_technique.
3. Suppress-by-evidence, escalate-by-category. If behavior matches a documented benign pattern (scheduled scan, service account job, VPN roaming, test host) close as false_positive. If you see a high-signal technique (log tampering, credential dumping, MFA fatigue, web shell, persistence) treat it as a likely real attack.
4. Be conservative. When evidence is genuinely ambiguous or a false negative would be costly, use disposition \"suspicious\" or \"investigate\" rather than guessing.
5. Map techniques to MITRE ATT&CK using get_mitre_technique where relevant.
6. Recommend concrete containment/remediation actions. Destructive or impactful actions (disable account, isolate host, block IP, kill process, revert change) must have requires_approval=true.
7. Finish ONLY via the submit_verdict tool. Do not summarize in prose and stop — the verdict must be committed through the tool, with all fields filled.
8. Keep the summary in plain English a tired analyst can read in 30 seconds."""

VERDICT_EXTRA_HINT = (
    "\n\nThe submit_verdict tool is the only way to finish this investigation. "
    "When you call it you must include every required field. Do not call any other tool after it."
)


def build_brief(ctx: ToolContext) -> str:
    case = ctx.case
    alerts = ctx.case_alerts()
    ev_count = len(ctx.case_events())

    alert_lines = [
        f"- [{a.severity.value}] {a.rule_name} ({a.source}): {a.title}\n  {a.description}"
        for a in alerts
    ]

    entity_line = " | ".join(
        [f"users={', '.join(case.entities.users)}"] +
        [f"ips={', '.join(case.entities.ips)}"] +
        [f"hosts={', '.join(case.entities.hosts)}"]
    )

    return f"""INCIDENT TO TRIAGE
===================
Case: {case.title}
Correlated alerts ({len(alerts)}): 
{chr(10).join(alert_lines)}

Incident window: {case.window_start.isoformat()} -> {case.window_end.isoformat()}
Entities involved: {entity_line}
Correlated raw events: {ev_count}
Signals: {', '.join(case.signals) if case.signals else 'none flagged'}
Techniques so far: {', '.join(case.techniques) if case.techniques else 'unknown'}

Relevant pre-computed threat-intel reputation for entities in this case is available via lookup_ip_reputation.

Investigate with the tools, then commit a verdict via submit_verdict.
Remember to check for benign explanations (vendor onboarding, scheduled jobs, service accounts,
VPN roaming, designated test hosts) before calling something a true positive,
and to escalate confidently when you see attacker-behavior signatures."""


def finalize_verdict(ctx: ToolContext, verdict: Verdict, model: str, llm_used: bool) -> Verdict:
    verdict.model = model
    verdict.llm_used = llm_used
    verdict.evidence = build_evidence_from_case(ctx, verdict)
    verdict.timeline = build_timeline_from_case(ctx)
    verdict.tool_trace = [
        ToolCallRecord(step=i + 1, tool=r["tool"], input=r.get("input", {}), output=r.get("output", ""),
                       timestamp=datetime.fromisoformat(r.get("timestamp", datetime.utcnow().isoformat())))
        for i, r in enumerate(ctx.tool_trace)
    ]
    return verdict


def run_claude_investigation(
    ctx: ToolContext,
    model: str = None,
    max_iterations: int = None,
    max_tokens: int = None,
) -> Verdict:
    import anthropic

    model = model or settings.TRIAGE_MODEL
    max_iterations = max_iterations or settings.MAX_TOOL_ITERATIONS
    max_tokens = max_tokens or settings.MAX_TOKENS

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    from .tools import TOOL_FUNCS, tool_schemas

    messages: List[Dict[str, Any]] = [{
        "role": "user",
        "content": [{"type": "text", "text": build_brief(ctx) + VERDICT_EXTRA_HINT}],
    }]

    final: Dict[str, Any] = {}
    finished = False
    for step in range(max_iterations):
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT.format(org=settings.ORGANIZATION),
            tools=tool_schemas(),
            messages=messages,
        )

        assistant_blocks: List[Dict[str, Any]] = []
        tool_calls: List[Dict[str, Any]] = []
        for block in resp.content:
            if block.type == "text":
                assistant_blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_blocks.append({"type": "tool_use", "id": block.id,
                                         "name": block.name, "input": block.input})
                tool_calls.append({"id": block.id, "name": block.name, "input": block.input})

        if not tool_calls:
            # model stopped talking; push back toward the verdict tool
            messages.append({"role": "assistant", "content": assistant_blocks})
            messages.append({"role": "user", "content": [{"type": "text",
                             "text": "You must finish by calling submit_verdict with a full verdict."}]})
            continue

        messages.append({"role": "assistant", "content": assistant_blocks})

        results = []
        for call in tool_calls:
            fn = TOOL_FUNCS.get(call["name"])
            try:
                if fn is None:
                    out = f"ERROR: unknown tool {call['name']}"
                else:
                    out = fn(ctx, **call["input"])
            except Exception as exc:  # e.g. pydantic validation on submit_verdict
                out = (f"ERROR from tool {call['name']}: {exc}. Read the error and retry with "
                       "correct fields. Do not call submit_verdict again with the same invalid payload.")
            results.append({"type": "tool_result", "tool_use_id": call["id"], "content": out})
            if call["name"] == "submit_verdict" and ctx.submitted_verdict is not None:
                finished = True
                final = ctx.submitted_verdict

        messages.append({"role": "user", "content": results})
        if finished:
            break

    if not final:
        raise RuntimeError("Claude agent did not commit a verdict within the step budget; "
                           "falling back to deterministic investigation.")

    finalize_verdict(ctx, final, model, llm_used=True)
    return final