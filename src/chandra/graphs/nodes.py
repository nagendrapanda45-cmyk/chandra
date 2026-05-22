"""LangGraph node implementations for the Chandra observation pipeline.

Topology:

::

    START
      └─► onboard_account
            └─► fanout_observers (returns Send(...) per KRA)
                  ├─► observe_cost
                  ├─► observe_security
                  ├─► observe_compliance
                  ├─► observe_performance
                  └─► observe_reliability
                        └─► analyze
                              └─► compose_briefing
                                    └─► persist
                                          └─► END
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from langgraph.types import Send

from chandra.aws.client_factory import get_default_factory
from chandra.aws.regions import active_regions
from chandra.briefing.composer import (
    compose_executive_summary,
    deterministic_rank,
    render_markdown,
    score_findings,
)
from chandra.briefing.schemas import AnalyzedFinding, Finding
from chandra.db.models import Briefing, Finding as FindingRow, Run
from chandra.db.session import session_scope
from chandra.graphs.state import ChandraState
from chandra.logger import get_logger
from chandra.tools import compliance, cost, performance, reliability, security
from chandra.tools.base import DetectorContext

logger = get_logger(__name__)


# ============================================================================
# PARALLELIZED KRA RUNNERS
# ============================================================================


def _run_detector_safe(
    detector_fn: Any,
    ctx: DetectorContext,
) -> tuple[list[Finding], list[str]]:
    """Run a single detector with exception handling."""
    try:
        findings = detector_fn(ctx)
        return (findings if findings else [], [])
    except Exception as exc:
        error_msg = f"Detector {detector_fn.__name__} failed: {str(exc)}"
        logger.error("detector.exception", detector=detector_fn.__name__, error=str(exc))
        return ([], [error_msg])


def run_kra_parallel(
    detectors: list[Any],
    ctx: DetectorContext,
    max_workers: int = 5,
) -> list[Finding]:
    """Run multiple detectors in parallel, collect findings + errors."""
    all_findings: list[Finding] = []
    all_errors: list[str] = []

    if not detectors:
        logger.warning("run_kra_parallel.no_detectors", ctx=ctx)
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_detector_safe, detector, ctx): detector.__name__
            for detector in detectors
        }

        for future in as_completed(futures):
            detector_name = futures[future]
            try:
                findings, errors = future.result(timeout=30)
                all_findings.extend(findings)
                all_errors.extend(errors)
                logger.debug(
                    "detector.completed",
                    detector=detector_name,
                    findings=len(findings),
                )
            except TimeoutError:
                logger.error("detector.timeout", detector=detector_name)
                all_errors.append(f"Detector {detector_name} timed out")
            except Exception as exc:
                logger.error(
                    "detector.future_exception",
                    detector=detector_name,
                    error=str(exc),
                )
                all_errors.append(f"Detector {detector_name} failed: {str(exc)}")

    # Merge errors into ctx for reporting
    ctx.errors.extend(all_errors)

    return all_findings


# ============================================================================
# KRA-SPECIFIC RUNNERS (using exact function names from your code)
# ============================================================================


def run_all_cost(ctx: DetectorContext) -> list[Finding]:
    """Run all cost detectors in parallel."""
    detectors = [
        cost.find_idle_ec2,
        cost.find_unattached_ebs,
        cost.find_unused_eips,
        cost.find_untagged_billable,
    ]
    return run_kra_parallel(detectors, ctx, max_workers=4)


def run_all_security(ctx: DetectorContext) -> list[Finding]:
    """Run all security detectors in parallel."""
    detectors = [
        security.find_public_s3_buckets,
        security.find_open_security_groups,
        security.find_stale_access_keys,
        security.check_root_mfa,
        security.find_overly_permissive_iam,
    ]
    return run_kra_parallel(detectors, ctx, max_workers=5)


def run_all_compliance(ctx: DetectorContext) -> list[Finding]:
    """Run all compliance detectors in parallel."""
    detectors = [
        compliance.check_cloudtrail_multi_region,
        compliance.check_config_recorder,
        compliance.check_encryption_at_rest_rds,
        compliance.check_encryption_at_rest_ebs,
        compliance.check_s3_default_encryption,
    ]
    return run_kra_parallel(detectors, ctx, max_workers=5)


def run_all_performance(ctx: DetectorContext) -> list[Finding]:
    """Run all performance detectors in parallel."""
    # If performance module has ALL_DETECTORS, use it
    if hasattr(performance, 'ALL_DETECTORS'):
        detectors = list(performance.ALL_DETECTORS)
    else:
        # Fallback: scan for detect_* and check_* functions
        detectors = [
            func for name, func in vars(performance).items()
            if (name.startswith("detect_") or name.startswith("check_"))
            and callable(func)
            and not name.startswith("_")
        ]
    
    if not detectors:
        logger.warning("performance.no_detectors_found")
        return []
    
    return run_kra_parallel(detectors, ctx, max_workers=4)


def run_all_reliability(ctx: DetectorContext) -> list[Finding]:
    """Run all reliability detectors in parallel."""
    # If reliability module has ALL_DETECTORS, use it
    if hasattr(reliability, 'ALL_DETECTORS'):
        detectors = list(reliability.ALL_DETECTORS)
    else:
        # Fallback: scan for detect_* and check_* functions
        detectors = [
            func for name, func in vars(reliability).items()
            if (name.startswith("detect_") or name.startswith("check_"))
            and callable(func)
            and not name.startswith("_")
        ]
    
    if not detectors:
        logger.warning("reliability.no_detectors_found")
        return []
    
    return run_kra_parallel(detectors, ctx, max_workers=4)


KRA_RUNNERS = {
    "cost": run_all_cost,
    "security": run_all_security,
    "compliance": run_all_compliance,
    "performance": run_all_performance,
    "reliability": run_all_reliability,
}


# ---------------------------------------------------------------------------
# Node: onboard_account
# ---------------------------------------------------------------------------


def onboard_account(state: ChandraState) -> dict[str, Any]:
    """Validate the run, resolve regions, and seed the inventory."""
    factory = get_default_factory()
    account_id = state.get("account_id") or factory.account_id()
    regions = state.get("regions") or active_regions(account_id, factory=factory)
    logger.info(
        "graph.onboard",
        run_id=state.get("run_id"),
        account_id=account_id,
        regions=regions,
    )
    return {
        "account_id": account_id,
        "regions": regions,
        "raw_findings": {},
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Fanout router
# ---------------------------------------------------------------------------


def fanout_observers(state: ChandraState) -> list[Send]:
    """Emit one ``Send(...)`` per KRA so observers run concurrently.

    LangGraph's parallel-branch primitive. Each observer receives the same
    state snapshot; their partial returns are merged by the reducers defined
    in :mod:`chandra.graphs.state`.
    """
    return [
        Send(f"observe_{kra}", state)
        for kra in ("cost", "security", "compliance", "performance", "reliability")
    ]


# ---------------------------------------------------------------------------
# Observer nodes — one per KRA
# ---------------------------------------------------------------------------


def _run_observer(kra: str, state: ChandraState) -> dict[str, Any]:
    """Run a single KRA observer with error handling."""
    try:
        runner = KRA_RUNNERS.get(kra)
        if not runner:
            logger.error("graph.observe.unknown_kra", kra=kra)
            return {
                "raw_findings": {kra: []},
                "errors": [f"Unknown KRA: {kra}"],
            }

        ctx = DetectorContext(
            run_id=state["run_id"],
            account_id=state["account_id"],
            regions=list(state.get("regions", [])),
        )
        findings: list[Finding] = runner(ctx)
        
        # Guard against None findings
        if findings is None:
            findings = []
        
        logger.info(
            "graph.observe",
            kra=kra,
            run_id=state["run_id"],
            count=len(findings),
            errors=len(ctx.errors),
        )
        return {
            "raw_findings": {kra: findings},
            "errors": ctx.errors,
        }
    except Exception as exc:
        error_msg = f"KRA {kra} failed: {str(exc)}"
        logger.error("graph.observe.exception", kra=kra, error=str(exc))
        return {
            "raw_findings": {kra: []},
            "errors": [error_msg],
        }


def observe_cost(state: ChandraState) -> dict[str, Any]:
    return _run_observer("cost", state)


def observe_security(state: ChandraState) -> dict[str, Any]:
    return _run_observer("security", state)


def observe_compliance(state: ChandraState) -> dict[str, Any]:
    return _run_observer("compliance", state)


def observe_performance(state: ChandraState) -> dict[str, Any]:
    return _run_observer("performance", state)


def observe_reliability(state: ChandraState) -> dict[str, Any]:
    return _run_observer("reliability", state)


# ---------------------------------------------------------------------------
# Analyze (LLM rank + dedup, deterministic fallback)
# ---------------------------------------------------------------------------


def analyze(state: ChandraState) -> dict[str, Any]:
    """Rank + dedup findings and compute the per-KRA scorecard.

    Calls the LLM via :mod:`chandra.briefing.composer` for narrative ranking,
    but falls back to deterministic severity-weight ordering on any failure.
    """
    raw = state.get("raw_findings") or {}
    
    # Guard against None and empty
    if not raw:
        logger.warning("graph.analyze.no_findings", run_id=state.get("run_id"))
        return {
            "analyzed_findings": [],
            "scorecard": {},
        }
    
    flat: list[Finding] = []
    for kra_findings in raw.values():
        if kra_findings:  # Guard against None
            flat.extend(kra_findings)

    # Guard: don't call LLM if no findings
    if not flat:
        logger.warning("graph.analyze.empty_flat", run_id=state.get("run_id"))
        analyzed = []
        scorecard = {}
    else:
        try:
            analyzed: list[AnalyzedFinding] = deterministic_rank(flat)
            scorecard = score_findings(raw)
        except Exception as exc:
            logger.error("graph.analyze.exception", error=str(exc))
            analyzed = []
            scorecard = {}

    logger.info(
        "graph.analyze",
        run_id=state["run_id"],
        total=len(flat),
        analyzed=len(analyzed),
        scorecard=scorecard if scorecard else "empty",
    )
    
    return {
        "analyzed_findings": analyzed,
        "scorecard": scorecard,
    }


# ---------------------------------------------------------------------------
# Compose briefing (LLM narrative)
# ---------------------------------------------------------------------------


def compose_briefing(state: ChandraState) -> dict[str, Any]:
    """Render the markdown + JSON briefing for the run."""
    analyzed = state.get("analyzed_findings") or []
    scorecard = state.get("scorecard") or {}
    raw = state.get("raw_findings") or {}

    # Flatten findings with guards
    flat: list[Finding] = []
    if raw:
        for kra_findings in raw.values():
            if kra_findings:  # Guard against None
                flat.extend(kra_findings)

    try:
        # Only call LLM if we have findings
        if analyzed:
            executive = compose_executive_summary(analyzed, scorecard)
        else:
            executive = "No findings detected."
            
    except Exception as exc:
        logger.error("graph.compose_briefing.executive_summary_failed", error=str(exc))
        executive = "Executive summary generation failed."

    metadata = {
        "regions": state.get("regions", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "errors": state.get("errors", []),
    }
    
    try:
        briefing_md, briefing_json = render_markdown(
            run_id=state["run_id"],
            account_id=state["account_id"],
            scorecard=scorecard,
            executive_summary=executive,
            top_findings=analyzed[:10] if analyzed else [],
            all_findings=flat if flat else [],
            metadata=metadata,
        )
    except Exception as exc:
        logger.error("graph.compose_briefing.render_failed", error=str(exc))
        briefing_md = f"# Briefing Failed\n\nError: {str(exc)}"
        briefing_json = {}

    return {"briefing_md": briefing_md, "briefing_json": briefing_json}


# ---------------------------------------------------------------------------
# Persist (only node allowed to write to Postgres outside migrations)
# ---------------------------------------------------------------------------


def persist(state: ChandraState) -> dict[str, Any]:
    """Write run, findings and briefing rows. Idempotent on (run_id).
    
    Gracefully handles missing psycopg2 or Postgres connection.
    """
    run_id = state["run_id"]
    account_id = state["account_id"]
    raw = state.get("raw_findings") or {}
    scorecard = state.get("scorecard") or {}
    briefing_md = state.get("briefing_md") or ""
    errors = state.get("errors") or []

    # Flatten findings with guards
    flat: list[Finding] = []
    if raw:
        for kra_findings in raw.values():
            if kra_findings:  # Guard against None
                flat.extend(kra_findings)

    # Try to persist to Postgres, but don't fail the entire graph if DB is unavailable
    try:
        with session_scope() as sess:
            # Upsert run record
            run = sess.get(Run, run_id)
            if run is None:
                run = Run(
                    id=run_id,
                    account_id=account_id,
                    status="completed",
                    finished_at=datetime.now(timezone.utc),
                    errors_json=errors,
                )
                sess.add(run)
            else:
                run.account_id = account_id
                run.status = "completed"
                run.finished_at = datetime.now(timezone.utc)
                run.errors_json = errors

            # Replace findings for this run to keep persist idempotent.
            sess.query(FindingRow).filter(FindingRow.run_id == run_id).delete()
            for f in flat:
                try:
                    sess.add(
                        FindingRow(
                            run_id=run_id,
                            kra=f.kra,
                            severity=f.severity,
                            detector_id=f.detector_id,
                            resource_arn=f.resource_arn,
                            resource_type=f.resource_type,
                            region=f.region,
                            title=f.title,
                            evidence_jsonb=f.evidence,
                            recommendation=f.recommendation,
                        )
                    )
                except Exception as exc:
                    logger.error(
                        "graph.persist.finding_insert_failed",
                        run_id=run_id,
                        finding_id=f.detector_id,
                        error=str(exc),
                    )

            # Upsert briefing
            existing_briefing = (
                sess.query(Briefing).filter(Briefing.run_id == run_id).one_or_none()
            )
            if existing_briefing is None:
                sess.add(
                    Briefing(
                        run_id=run_id,
                        scorecard_jsonb=scorecard,
                        markdown_text=briefing_md,
                        findings_count=len(flat),
                    )
                )
            else:
                existing_briefing.scorecard_jsonb = scorecard
                existing_briefing.markdown_text = briefing_md
                existing_briefing.findings_count = len(flat)

            sess.commit()
            logger.info(
                "graph.persist.success",
                run_id=run_id,
                findings=len(flat),
            )

    except ModuleNotFoundError as exc:
        # psycopg2 not installed — log and continue
        logger.warning(
            "graph.persist.psycopg2_missing",
            error=str(exc),
            advice="Install: pip install psycopg2-binary",
        )
    except Exception as exc:
        # Other DB errors — log and continue (don't crash the graph)
        logger.warning(
            "graph.persist.db_error_non_fatal",
            run_id=run_id,
            error=str(exc),
            advice="Check Postgres connection and psycopg2 installation",
        )

    return {}