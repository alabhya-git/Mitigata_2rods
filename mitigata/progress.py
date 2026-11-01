"""Small live snapshots: never rebuild or serialize the full evidence archive."""

from __future__ import annotations

import json
import time


def snapshot(store, run_id):
    from .ai import budget_snapshot

    run = store.run(run_id)
    counts = dict(
        store.db.execute("SELECT kind,count(*) FROM records WHERE run_id=? GROUP BY kind", (run_id,))
    )
    tasks = [
        dict(r)
        for r in store.db.execute(
            "SELECT role,status,count(*) AS n FROM tasks WHERE run_id=? GROUP BY role,status", (run_id,)
        )
    ]
    stats = {}
    for row in tasks:
        stats.setdefault(row["role"], {})[row["status"]] = row["n"]
    findings = store.records(run_id, "finding")
    audits = dict(
        store.db.execute(
            "SELECT json_extract(data,'$.status'),count(*) FROM records WHERE run_id=? AND kind='audit' GROUP BY 1",
            (run_id,),
        )
    )
    frontier = store.get(run_id, "frontier", "tcp")
    planned = frontier["data"]["total_pairs"] if frontier else 0
    tested = counts.get("port", 0)
    observer = store.record_page(run_id, "observer", 0, 1)
    briefings = []
    for row in store.db.execute(
        "SELECT producer,max(updated) FROM records WHERE run_id=? AND kind='briefing' GROUP BY producer",
        (run_id,),
    ):
        b = store.db.execute(
            "SELECT * FROM records WHERE run_id=? AND kind='briefing' AND producer=? ORDER BY updated DESC LIMIT 1",
            (run_id, row[0]),
        ).fetchone()
        briefings.append(store._record(b))
    unresolved = sum(f["data"]["status"] in {"candidate", "inconclusive"} for f in findings)
    confirmed = sum(f["data"]["status"] == "confirmed" for f in findings)
    metrics = {
        "scope_pairs_planned": planned,
        "scope_pairs_tested": tested,
        "scope_pairs_untested": max(0, planned - tested),
        "scope_pairs_scheduled": frontier["data"]["next_index"] if frontier else 0,
        "tcp_inventory_fraction": tested / planned if planned else None,
        "services_discovered": counts.get("service", 0),
        "hosts_discovered": counts.get("asset", 0),
        "endpoints": counts.get("endpoint", 0),
        "confirmed": confirmed,
        "rejected": sum(f["data"]["status"] == "rejected" for f in findings),
        "unresolved": unresolved,
        "validated_flags": store.db.execute(
            "SELECT count(*) FROM records WHERE run_id=? AND kind='flag' AND json_extract(data,'$.status')='validated'",
            (run_id,),
        ).fetchone()[0],
        "captured_flags": counts.get("flag", 0),
        "ai": budget_snapshot(store, run_id),
        "requests_allowed": audits.get("allowed", 0),
        "blocked_attempts": audits.get("blocked", 0),
        "failed_tasks": sum(s.get("failed", 0) for s in stats.values()),
        "elapsed_seconds": round((run["ended"] or time.time()) - run["started"], 3),
        "max_briefing_bytes": store.db.execute(
            "SELECT coalesce(max(json_extract(data,'$.bytes')),0) FROM records WHERE run_id=? AND kind='briefing'",
            (run_id,),
        ).fetchone()[0],
        "independent_egress_observer": observer[0]["data"]["status"] if observer else "unavailable",
        "independently_observed_scope_violations": observer[0]["data"].get("transmitted_scope_violations")
        if observer
        else None,
    }
    events = [
        {**dict(r), "data": json.loads(r["data"])}
        for r in store.db.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 50", (run_id,))
    ][::-1]
    phases = {
        p: "not_performed"
        for p in (
            "Pre-engagement Interactions",
            "Intelligence Gathering",
            "Threat Modeling",
            "Vulnerability Analysis",
            "Exploitation",
            "Post-Exploitation",
            "Reporting",
        )
    }
    for row in store.db.execute("SELECT DISTINCT phase FROM events WHERE run_id=?", (run_id,)):
        phases[row[0]] = "performed"
    nodes, edges = store.records(run_id, "graph_node"), store.records(run_id, "graph_edge")
    return store.public(
        run_id,
        {
            "run": run,
            "metrics": metrics,
            "agent_stats": stats,
            "phases": phases,
            "findings": findings[:200],
            "verifications": store.record_page(run_id, "verification", 0, 200),
            "tasks": [
                store.task(r[0])
                for r in store.db.execute(
                    "SELECT id FROM tasks WHERE run_id=? AND status='running' LIMIT 128", (run_id,)
                )
            ],
            "briefings": briefings,
            "events": events,
            "graph": {"nodes": nodes, "edges": edges},
            "services": store.record_page(run_id, "service", 0, 200),
            "artifacts": store.record_page(run_id, "artifact", 0, 50),
            "capabilities": store.record_page(run_id, "capability", 0, 50),
            "cases": store.record_page(run_id, "investigation_case", 0, 50),
            "flags": store.record_page(run_id, "flag", 0, 100),
            "handoffs": store.record_page(run_id, "handoff", max(0, counts.get("handoff", 0) - 10), 10),
            "counts": counts,
            "snapshot": True,
        },
    )
