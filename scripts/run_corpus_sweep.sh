#!/usr/bin/env bash
# Resumable, parallel corpus sweep for the paper's results table.
#
# Runs the full pipeline over every corpus tool, RUNS times. Cross-run variance
# comes from LLM nondeterminism (there is no --seed flag); aggregate_runs.py
# --by-tool groups these into per-tool mean +/- std.
#
# Parallelism is across TOOLS (separate processes), never within a run:
# attack_parallelism stays 1 inside each process, so per-run ordering remains
# deterministic and the speedup costs nothing methodologically.
#
# The Cloudflare quick tunnel is ephemeral and WILL drop during a long run, so
# completed outputs are skipped on restart. After a failure just re-run this.
#
#   bash scripts/run_corpus_sweep.sh                 # 5 runs, 3 tools at a time
#   RUNS="1 2 3" JOBS=4 bash scripts/run_corpus_sweep.sh
RUNS="${RUNS:-1 2 3 4 5}"
JOBS="${JOBS:-3}"
CONFIG="${CONFIG:-config.yaml}"
BENIGN="${BENIGN:-benign_tasks_recorded}"
ROOT="${ROOT:-hardener_output/corpus_sweep}"

run_one() {
  tool="$1"; run="$2"
  name="$(basename "$tool" .yaml)"
  out="$ROOT/run$run/$name"
  if [ -f "$out/report.json" ]; then
    echo "[skip] run=$run $name"
    return 0
  fi
  mkdir -p "$out"
  echo "[run ] run=$run $name  $(date +%H:%M:%S)"
  if python -m agent_hardener.cli analyze \
       --tool-file "$tool" --config "$CONFIG" \
       --benign-dir "$BENIGN" \
       --output-dir "$out" >> "$out/run.log" 2>&1; then
    echo "[ ok ] run=$run $name  $(date +%H:%M:%S)"
  else
    echo "[FAIL] run=$run $name - see $out/run.log"
  fi
}

for run in $RUNS; do
  active=0
  for tool in mcp_tools/*.yaml; do
    run_one "$tool" "$run" &
    active=$((active + 1))
    if [ "$active" -ge "$JOBS" ]; then
      wait -n 2>/dev/null || wait
      active=$((active - 1))
    fi
  done
  wait
  echo "--- run $run complete: $(date) ---"
done
echo "sweep finished: $(date)"
