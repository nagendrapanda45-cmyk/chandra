"""Fast Chandra run with MOCK detectors — no AWS, no Bedrock, no Postgres."""
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import time
import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

# ── 1. Mock detector modules (no AWS API calls) ──────────────────────────────
import mock_detectors
sys.modules['chandra.tools.cost'] = mock_detectors
sys.modules['chandra.tools.security'] = mock_detectors
sys.modules['chandra.tools.compliance'] = mock_detectors
sys.modules['chandra.tools.performance'] = mock_detectors
sys.modules['chandra.tools.reliability'] = mock_detectors

# ── 2. Disable Bedrock — composer falls back to deterministic instantly ───────
# Setting a module to None in sys.modules causes ImportError on 'from X import Y'
# which is exactly what compose_executive_summary and llm_rank catch.
sys.modules['langchain_aws'] = None

# ── 3. Import chandra (mocks must be set before this) ────────────────────────
from chandra.graphs.chandra_graph import build_graph
from langgraph.checkpoint.memory import MemorySaver

# ── 4. No-op session for persist node (avoids Postgres TCP timeout) ───────────
@contextmanager
def _noop_session():
    yield MagicMock()


print("=" * 70)
print("CHANDRA FAST TEST (MOCK — no AWS / Bedrock / Postgres)")
print("=" * 70)

start_build = time.time()
print("\n[1/3] Building graph...")
graph = build_graph(checkpointer=MemorySaver())
build_time = time.time() - start_build
print(f"  Graph built in {build_time:.2f}s")

run_id = str(uuid.uuid4())
print(f"\n[2/3] Running Chandra (run_id={run_id[:8]}...)...")

start_run = time.time()
with patch("chandra.graphs.nodes.session_scope", _noop_session):
    final_state = graph.invoke(
        {
            "run_id": run_id,
            "account_id": "827295473120",
            "regions": ["us-east-1"],
            "raw_findings": {},
            "errors": [],
        },
        config={"configurable": {"thread_id": run_id}},
    )
run_time = time.time() - start_run
print(f"  Completed in {run_time:.2f}s")

print(f"\n[3/3] Results:")
print("=" * 70)

briefing_md = final_state.get("briefing_md", "No briefing generated")
scorecard = final_state.get("scorecard", {})

print("\nBRIEFING:")
print("-" * 70)
output = str(briefing_md)
print(output[:1200] if len(output) > 1200 else output)
print("-" * 70)

print("\nSCORECARD:")
if hasattr(scorecard, "as_dict"):
    print(scorecard.as_dict())
else:
    print(scorecard)

total = build_time + run_time
print("\n" + "=" * 70)
print(f"TOTAL: {total:.2f}s")
print("=" * 70)
