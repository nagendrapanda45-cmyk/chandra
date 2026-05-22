"""Fast Chandra run — skip Postgres, use MemorySaver."""
import time
import uuid
from chandra.graphs.chandra_graph import build_graph
from langgraph.checkpoint.memory import MemorySaver

print("Building graph with MemorySaver (skip Postgres)...")
start_build = time.time()
graph = build_graph(checkpointer=MemorySaver())
print(f"✓ Graph built in {time.time() - start_build:.2f}s\n")

run_id = str(uuid.uuid4())
print(f"Running Chandra with run_id: {run_id}")
print("=" * 60)

start_total = time.time()

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

total_time = time.time() - start_total
print("=" * 60)
print(f"\n✓ Execution completed in {total_time:.2f}s\n")

print("BRIEFING MARKDOWN:")
print("-" * 60)
print(final_state.get("briefing_md", "No briefing generated"))
print("-" * 60)

print("\nSCORECARD:")
print("-" * 60)
print(final_state.get("scorecard", {}))
print("-" * 60)

print(f"\nTotal execution time: {total_time:.2f}s")