from __future__ import annotations

import html
import json
from pathlib import Path

from .evidence import EvidenceStore
from .store import Store


def build_report(store: Store, run_id: str) -> dict:
    from .ai import budget_snapshot

    run = store.run(run_id)
    findings = store.records(run_id, "finding")
    confirmed = [f for f in findings if f["data"]["status"] == "confirmed"]
    unresolved = [f for f in findings if f["data"]["status"] in {"candidate", "inconclusive"}]
    checks = store.records(run_id, "check")
    audits = store.records(run_id, "audit")
    observers = store.records(run_id, "observer")
    observer = observers[-1]["data"] if observers else None
    events = store.events(run_id, limit=5000)
    task_list = store.tasks(run_id)
    frontier = store.get(run_id, "frontier", "tcp")
    planned_pairs = frontier["data"]["total_pairs"] if frontier else 0
    tested_pairs = store.count_records(run_id, "port")
    elapsed = (run["ended"] or __import__("time").time()) - run["started"]
    phases = {
        phase: "not_performed"
        for phase in (
            "Pre-engagement Interactions",
            "Intelligence Gathering",
            "Threat Modeling",
            "Vulnerability Analysis",
            "Exploitation",
            "Post-Exploitation",
            "Reporting",
        )
    }
    for event in events:
        phases[event["phase"]] = "performed"
    edges = store.records(run_id, "graph_edge")
    metrics = {
        "ai": budget_snapshot(store, run_id),
        "captured_flags": store.count_records(run_id, "flag"),
        "scope_pairs_planned": planned_pairs,
        "scope_pairs_scheduled": frontier["data"]["next_index"] if frontier else 0,
        "scope_pairs_tested": tested_pairs,
        "scope_pairs_untested": max(0, planned_pairs - tested_pairs),
        "tcp_inventory_fraction": tested_pairs / planned_pairs if planned_pairs else None,
        "execution_profile": run["manifest"].get("execution_profile", "local"),
        "hosts_discovered": len(store.records(run_id, "asset")),
        "services_discovered": len(store.records(run_id, "service")),
        "endpoints": len(store.records(run_id, "endpoint")),
        "confirmed": len(confirmed),
        "rejected": sum(f["data"]["status"] == "rejected" for f in findings),
        "unresolved": len(unresolved),
        "declared_positive_findings": len(confirmed) + len(unresolved),
        "verified_proportion": len(confirmed) / (len(confirmed) + len(unresolved))
        if confirmed or unresolved
        else None,
        "requests_allowed": sum(a["data"]["status"] == "allowed" for a in audits),
        "blocked_attempts": sum(a["data"]["status"] == "blocked" for a in audits),
        "independently_observed_scope_violations": observer.get("transmitted_scope_violations")
        if observer
        else None,
        "independent_egress_observer": observer["status"] if observer else "unavailable",
        "ground_truth_host_recall": None,
        "ground_truth_service_recall": None,
        "ground_truth_issue_recall": None,
        "ground_truth_false_alarm_share": None,
        "elapsed_seconds": round(elapsed, 3),
        "human_interventions_during_run": int(bool(run["cancel_requested"])),
        "failed_tasks": sum(t["status"] == "failed" for t in task_list),
        "max_briefing_bytes": max((b["data"]["bytes"] for b in store.records(run_id, "briefing")), default=0),
        "validated_flags": sum(f["data"]["status"] == "validated" for f in store.records(run_id, "flag")),
    }
    report = store.public(
        run_id,
        {
            "schema_version": "1.0",
            "run": run,
            "metrics": metrics,
            "phases": phases,
            "assets": store.records(run_id, "asset"),
            "services": store.records(run_id, "service"),
            "ports": store.records(run_id, "port"),
            "endpoints": store.records(run_id, "endpoint"),
            "artifacts": store.records(run_id, "artifact"),
            "findings": findings,
            "verifications": store.records(run_id, "verification"),
            "handoffs": store.records(run_id, "handoff"),
            "flags": store.records(run_id, "flag"),
            "observations": store.records(run_id, "observation"),
            "discovery": store.records(run_id, "discovery"),
            "checks": checks,
            "audit": audits,
            "observer": observers,
            "graph": {"nodes": store.records(run_id, "graph_node"), "edges": edges},
            "attack_path": [e for e in edges if e["data"]["state"] == "verified_authorized_transition"],
            "attack_path_qualification": "Verified HTTP credential use and resource retrieval; no network pivot or multiple network hops are claimed.",
            "evidence": store.records(run_id, "evidence"),
            "briefings": store.records(run_id, "briefing"),
            "capabilities": store.records(run_id, "capability"),
            "ai_calls": store.records(run_id, "ai_call"),
            "investigation_cases": store.records(run_id, "investigation_case"),
            "agent_decisions": store.records(run_id, "agent_decision"),
            "authorities": store.records(run_id, "authority"),
            "tasks": task_list,
            "events": events,
            "limitations": [
                "Execution is restricted to the frozen scope and the recorded runtime profile; native guards are not a hostile-code sandbox.",
                "Recall and false-alarm share need separately isolated evaluator ground truth.",
                (
                    "Independent packet observation is qualified by its recorded protocols, sources, window and drop checks."
                    if observer
                    else "No independent egress observer was available; broker logs are not packet-capture proof."
                ),
                "Tool schemas, evidence isolation and scope enforcement constrain model actions; comprehensive LLM prompt-injection resistance has not been established.",
                "Supported checks are a bounded catalog, not arbitrary vulnerability discovery.",
                "Captured code candidates require an organizer checker or manual submission for authoritative validation. Same-IP hostname clues and unlisted services do not establish shadow-IT ownership.",
            ],
        },
    )
    # The captured flag is the engagement deliverable, so the operator-facing report reveals it in
    # full. Recovered intermediate credentials stay redacted by store.public above; only the flag
    # secret (roles include "Operator") is resolved here.
    for flag in report.get("flags", []):
        ref = flag["data"].get("secret_ref")
        if not ref:
            continue
        try:
            flag["data"]["value"] = store.reveal(run_id, ref, "Operator").get("exact_value")
        except PermissionError:
            continue
    return report


def capability_line(record: dict) -> tuple[str, str, str]:
    """Classify a capability record for honest reporting: (name, state, detail)."""
    data, name = record["data"], record["identity"]
    if "available" in data:
        if data["available"]:
            brokered = data.get("requests_brokered")
            return name, "available", f"{brokered} brokered requests" if brokered is not None else "ready"
        return name, "failed" if data.get("last_execution") == "failed" else "unavailable", data.get("reason", "")
    if "installed" in data or "live_allowed" in data:
        live = data.get("live_allowed") is True
        state = "live" if live else "present (offline)" if data.get("installed") else "not installed"
        return name, state, data.get("reason") or data.get("path") or ""
    if name == "runtime":
        state = "deterministic" if data.get("deterministic") else "llm-assisted"
        return name, state, f"{data.get('execution_profile', 'local')} profile"
    return name, "recorded", ""


def report_html(report: dict) -> str:
    esc = lambda x: html.escape(str(x), quote=True)
    rows = []
    for finding in report["findings"]:
        d = finding["data"]
        links = " ".join(f'<a href="evidence/{esc(e)}.json">{esc(e[:10])}</a>' for e in finding["evidence"])
        rows.append(
            f'<article><span class="status {esc(d["status"])}">{esc(d["status"])}</span>'
            f"<h3>{esc(d['title'])}</h3><code>{esc(d['target'])}</code><p>{esc(d['claim'])}</p>"
            f"<p><strong>Fix:</strong> {esc(d['remediation'])}</p><p>Evidence: {links}</p></article>"
        )
    flag_section = ""
    if report.get("flags"):
        flag_items = "".join(
            f'<article><span class="status confirmed">{esc(fl["data"]["status"])}</span>'
            f'<h3>Captured flag</h3>'
            f'<p class="flag">{esc(fl["data"].get("value") or "[access-controlled — export to reveal]")}</p>'
            f'<p>Source: <code>{esc(fl["data"].get("source_url", ""))}</code> · '
            f'basis: {esc(fl["data"].get("capture_basis", ""))}</p></article>'
            for fl in report["flags"]
        )
        flag_section = f"<h2>Captured flags</h2>{flag_items}"
    metric_rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v if v is not None else 'Not measured')}</td></tr>"
        for k, v in report["metrics"].items()
    )
    path_rows = "".join(
        f"<li>{esc(e['data']['relation'])} — {esc(e['data']['state'])}</li>" for e in report["attack_path"]
    )
    limitations = "".join(f"<li>{esc(item)}</li>" for item in report["limitations"])
    cap_rows = "".join(
        f"<tr><td>{esc(name)}</td><td class='status'>{esc(state)}</td><td>{esc(detail)}</td></tr>"
        for name, state, detail in (capability_line(c) for c in report["capabilities"])
    )
    case_rows = "".join(
        f"<li>{esc(c['data'].get('role', ''))}: {esc(c['data'].get('status', ''))}"
        + (f" — {esc(c['data']['reason'])}" if c["data"].get("reason") else "")
        + f" <code>{esc(c['data'].get('target', ''))}</code></li>"
        for c in report["investigation_cases"]
    )
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Mitigata evidence report</title><style>body{{font:15px/1.6 system-ui;max-width:1050px;margin:40px auto;padding:0 24px;color:#17212e;background:#f5f6f8}}h1{{font-size:30px}}h2{{margin-top:36px}}article{{padding:20px 0;border-bottom:1px solid #cdd3dc}}code{{overflow-wrap:anywhere}}.status{{font-size:12px;text-transform:uppercase}}.confirmed{{color:#126646}}.rejected{{color:#856420}}table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:6px;border-bottom:1px solid #dce0e6}}a{{color:#215aa0}}.flag{{font:600 20px/1.4 ui-monospace,Menlo,Consolas,monospace;color:#0f6b43;background:#e6f5ec;border:1px solid #b6e0c7;border-radius:8px;padding:12px 16px;overflow-wrap:anywhere}}</style>
<header><p>MITIGATA / EVIDENCE REPORT</p><h1>{esc(report["run"]["manifest"]["name"])}</h1><p>Run {esc(report["run"]["id"])} · {esc(report["run"]["status"])}</p><a href="report.json">Machine-readable report</a></header>
{flag_section}
<h2>Observed metrics</h2><table>{metric_rows}</table><h2>Findings and controls</h2>{"".join(rows) or "<p>No findings were declared.</p>"}
<h2>Verified access path</h2><p>{esc(report["attack_path_qualification"])}</p><ol>{path_rows}</ol>
<h2>PTES phases</h2><pre>{esc(json.dumps(report["phases"], indent=2))}</pre>
<h2>Runtime capabilities and degradation</h2><p>{esc(report["metrics"]["failed_tasks"])} task(s) failed during this run. Optional adapters are listed with their real availability; degraded tools are not counted as coverage.</p>
<table><tr><th>Adapter</th><th>State</th><th>Detail</th></tr>{cap_rows or "<tr><td colspan='3'>No capability records.</td></tr>"}</table>
{f"<h3>Investigation cases</h3><ul>{case_rows}</ul>" if case_rows else ""}
<h2>Limits of this result</h2><ul>{limitations}</ul></html>"""


def export_report(store: Store, evidence: EvidenceStore, run_id, directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    views = directory / "evidence"
    views.mkdir(exist_ok=True)
    report = build_report(store, run_id)
    for row in report["evidence"]:
        preview = evidence.view(run_id, row["id"])
        (views / (row["id"] + ".json")).write_text(json.dumps(preview, indent=2), encoding="utf-8")
    (directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (directory / "report.html").write_text(report_html(report), encoding="utf-8")
    return directory


def refresh_report_summary(store: Store, run_id, directory: Path):
    """Refresh final metrics after the first complete evidence bundle has been written."""
    report = build_report(store, run_id)
    (directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (directory / "report.html").write_text(report_html(report), encoding="utf-8")
