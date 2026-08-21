#!/usr/bin/env bash
# Keep the evaluation agent alive for the duration of a long corpus sweep.
#
# The agent server has died mid-sweep three times (OOM / upstream stall). When it
# dies every worker fails at once and the sweep loop exits, losing hours. This
# restarts it whenever the health probe fails, so a crash costs one tool run
# instead of the whole sweep.
: "${OLLAMA_BASE_URL:?set OLLAMA_BASE_URL}"
AGENT_MODEL="${AGENT_LLM_MODEL:-ollama/gemma3:27b}"
PORT="${PORT:-8080}"
LOG="${LOG:-/tmp/agent.log}"

start() {
  OLLAMA_BASE_URL="$OLLAMA_BASE_URL" AGENT_LLM_MODEL="$AGENT_MODEL" AGENT_MAX_STEPS="${AGENT_MAX_STEPS:-6}" \
    python -m uvicorn scripts.llm_agent_server:app --port "$PORT" >> "$LOG" 2>&1 &
  echo "$(date '+%H:%M:%S') watchdog: started agent (pid $!)"
}

start
while true; do
  sleep 60
  if ! curl -s -o /dev/null --max-time 90 "http://127.0.0.1:$PORT/"; then
    echo "$(date '+%H:%M:%S') watchdog: agent unhealthy - restarting"
    pid=$(netstat -ano 2>/dev/null | grep ":$PORT " | grep LISTENING | awk '{print $5}' | head -1)
    [ -n "$pid" ] && taskkill //PID "$pid" //F >/dev/null 2>&1
    sleep 3
    start
  fi
done
