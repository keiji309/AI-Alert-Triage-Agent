from __future__ import annotations

import argparse
import json
import sys

from src.triage import settings
from src.triage.agents.orchestrator import TriagePipeline
from src.triage.report.builder import ReportBuilder
from src.triage.store.storage import Store


def build_pipeline() -> TriagePipeline:
    return TriagePipeline()


def cmd_generate(args) -> None:
    pipe = build_pipeline()
    stats = pipe.generate(seed=args.seed)
    print("Generated demo dataset:")
    print(json.dumps(stats, indent=2))


def cmd_triage(args) -> None:
    pipe = build_pipeline()
    use_llm = not args.dry_run
    if not settings.ANTHROPIC_API_KEY and use_llm:
        print("No ANTHROPIC_API_KEY set — falling back to deterministic engine. "
              "Set it in .env to enable LLM triage.")
        use_llm = False
    if args.case:
        v = pipe.triage_case(args.case, llm=use_llm)
        print(f"[{v.case_id}] {v.disposition.value} ({v.confidence:.0%}) severity={v.severity.value}")
        print(v.summary)
        print(f"Report: {settings.REPORT_DIR / (v.case_id + '.md')}")
    else:
        results = pipe.triage_all(llm=use_llm)
        print(f"Triaged {len(results)} case(s):")
        for cid, r in results.items():
            print(f"  {cid}: {r}")


def cmd_report(args) -> None:
    store = Store()
    builder = ReportBuilder(store)
    if args.case:
        case = store.get_case(args.case)
        verdict = store.get_verdict(args.case)
        if not case or not verdict:
            print(f"No report for {args.case}", file=sys.stderr)
            sys.exit(1)
        print(builder.render_markdown(case, verdict))
    else:
        for row in store.list_cases():
            verdict = store.get_verdict(row["id"])
            state = f"{verdict.disposition.value} {verdict.confidence:.0%}" if verdict else row["status"]
            print(f"{row['id']:16s} {row['implied_severity']:9s} {state:24s} {row['title']}")


def cmd_serve(args) -> None:
    import uvicorn
    print(f"Dashboards at http://{args.host}:{args.port}")
    uvicorn.run("app.server:app", host=args.host, port=args.port, workers=args.workers,
                log_level="warning")


def cmd_status(args) -> None:
    store = Store()
    print(json.dumps(store.stats(), indent=2))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage", description="AI Alert Triage Agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate synthetic telemetry & correlate cases")
    g.add_argument("--seed", type=int, default=None)
    g.set_defaults(func=cmd_generate)

    t = sub.add_parser("triage", help="Investigate cases (LLM unless --dry-run)")
    t.add_argument("--case", default=None, help="single case id, else all open cases")
    t.add_argument("--dry-run", action="store_true", help="use deterministic engine only")
    t.set_defaults(func=cmd_triage)

    r = sub.add_parser("report", help="Print investigation reports")
    r.add_argument("--case", default=None)
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("serve", help="Run the web dashboard")
    s.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 for remote access)")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--workers", type=int, default=1)
    s.set_defaults(func=cmd_serve)

    st = sub.add_parser("status", help="Show dataset stats")
    st.set_defaults(func=cmd_status)

    d = sub.add_parser("demo", help="generate + triage + serve in one shot")
    d.add_argument("--port", type=int, default=8000)
    d.add_argument("--dry-run", action="store_true")
    d.set_defaults(func=lambda a: (cmd_generate(a), cmd_triage(a), cmd_serve(a)))

    args = p.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())