#!/usr/bin/env bash
#
# Clawsig Sentinel Shell — Deep Execution Observability
#
# Injected via BASH_ENV to auto-source into every bash subshell.
# Uses trap DEBUG to intercept commands before they execute.
# Logs structured JSONL to $CLAWSIG_TRACE_FILE.
#
# Coverage: ~85% of shell commands (exec/execSync with shell:true,
# bash -c, bash script.sh, nested bash invocations).
#
# Evasion: spawn() without shell, /bin/zsh, python -c, trap - DEBUG,
# env -i bash (strips BASH_ENV).

# ---- Guard: disable with env var ----
if [[ -n "$CLAWSIG_SENTINEL_DISABLE" ]]; then
  return 0 2>/dev/null || exit 0
fi

# ---- Guard: prevent double-load in nested subshells ----
if [[ -n "$__CLAWSIG_SENTINEL_LOADED" ]]; then
  return 0 2>/dev/null || exit 0
fi
export __CLAWSIG_SENTINEL_LOADED="1"

# ---- Fallback trace destination ----
: "${CLAWSIG_TRACE_FILE:=/tmp/clawsig-shell-trace-$$.jsonl}"

# ---- Source policy evaluator if present ----
_CLAWSIG_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$_CLAWSIG_SCRIPT_DIR/sentinel-shell-policy.sh" ]]; then
  # shellcheck disable=SC1091
  source "$_CLAWSIG_SCRIPT_DIR/sentinel-shell-policy.sh"
fi

# ---- Pattern lists for classification ----
# Network egress patterns (commands that make network connections)
_CLAWSIG_NET_PAT='curl |wget |nc |ncat |socat |ssh |scp |rsync |fetch |httpie '
_CLAWSIG_NET_PAT+='|python.*http|python.*request|python.*urllib|python.*socket'
_CLAWSIG_NET_PAT+='|node.*http|node.*fetch|node.*net\.'
_CLAWSIG_NET_PAT+='|ruby.*net/http|ruby.*open-uri'
_CLAWSIG_NET_PAT+='|php.*curl|php.*file_get_contents'

# Secret access patterns
_CLAWSIG_SECRET_PAT='\.env|_KEY|_SECRET|_TOKEN|_PASSWORD|_CREDENTIAL'
_CLAWSIG_SECRET_PAT+='|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ed25519|id_ecdsa'
_CLAWSIG_SECRET_PAT+='|\.ssh/|\.aws/|\.gnupg/|\.npmrc|\.pypirc'
_CLAWSIG_SECRET_PAT+='|credentials|secrets|\.clawsecrets'

# Env manipulation patterns
_CLAWSIG_ENV_PAT='unset.*HTTP_PROXY|unset.*HTTPS_PROXY|unset.*http_proxy|unset.*https_proxy'
_CLAWSIG_ENV_PAT+='|unset.*BASH_ENV|unset.*CLAWSIG'
_CLAWSIG_ENV_PAT+='|export PATH=|export SHELL=|export BASH_ENV='

# ---- Core debug trap function ----
_clawsig_debug_trap() {
  # Capture exit code before any of our commands change it
  local _cs_exit=$?
  local _cs_cmd="$BASH_COMMAND"

  # Skip empty commands, our own trap, prompt commands
  if [[ -z "$_cs_cmd" ]] || \
     [[ "$_cs_cmd" == *"_clawsig_debug_trap"* ]] || \
     [[ "$_cs_cmd" == *"PROMPT_COMMAND"* ]] || \
     [[ "$_cs_cmd" == "return "* ]] || \
     [[ "$_cs_cmd" == "true" ]]; then
    return "$_cs_exit"
  fi

  # ---- Policy enforcement (real-time blocking) ----
  if type evaluate_command >/dev/null 2>&1; then
    evaluate_command "$_cs_cmd"
    if [[ "$_CLAWSIG_EVAL_RESULT" == "BLOCK" ]]; then
      echo "[clawsig:policy] BLOCKED: $_cs_cmd" >&2
      # Log the blocked command to trace file
      local _cs_block_ts
      _cs_block_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
      local _cs_block_esc="$_cs_cmd"
      _cs_block_esc="${_cs_block_esc//\\/\\\\}"
      _cs_block_esc="${_cs_block_esc//\"/\\\"}"
      echo "{\"layer\":\"shell\",\"ts\":\"$_cs_block_ts\",\"pid\":$$,\"ppid\":$PPID,\"cwd\":\"${PWD//\\/\\\\}\",\"cmd\":\"$_cs_block_esc\",\"type\":\"policy_blocked\",\"target\":\"\",\"exit\":1}" >> "$CLAWSIG_TRACE_FILE"
      return 1
    fi
  fi

  # Timestamp: portable across macOS + Linux
  # macOS date doesn't support %N, so we use %s and fake ms
  local _cs_ts
  if _cs_ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null); then
    : # GNU date with %3N works
  else
    _cs_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  fi

  # Classify the command
  local _cs_type="command"
  local _cs_target=""

  # Check network egress
  if [[ "$_cs_cmd" =~ (curl |wget |nc |ncat |socat |ssh |scp |rsync ) ]] || \
     [[ "$_cs_cmd" =~ (python.*http|python.*request|python.*socket) ]] || \
     [[ "$_cs_cmd" =~ (node.*http|node.*fetch) ]]; then
    _cs_type="network_egress"
    # Extract URL/host from command
    local _cs_url
    _cs_url=$(echo "$_cs_cmd" | grep -oE 'https?://[^ "'"'"']+' | head -1)
    if [[ -n "$_cs_url" ]]; then
      _cs_target="$_cs_url"
    fi
  fi

  # Check secret access
  if [[ "$_cs_cmd" =~ (cat |less |more |head |tail |vim |nano |code |open ) ]] && \
     [[ "$_cs_cmd" =~ (\.env|_KEY|_SECRET|_TOKEN|\.pem|\.key|id_rsa|id_ed25519|\.ssh/|\.aws/) ]]; then
    _cs_type="secret_access"
    _cs_target=$(echo "$_cs_cmd" | grep -oE '[^ ]+\.(env|pem|key)|[^ ]*id_(rsa|ed25519|ecdsa)[^ ]*|[^ ]*\.ssh/[^ ]*|[^ ]*\.aws/[^ ]*' | head -1)
  fi

  # Check environment manipulation
  if [[ "$_cs_cmd" =~ (unset.*PROXY|unset.*proxy|unset.*BASH_ENV|unset.*CLAWSIG) ]] || \
     [[ "$_cs_cmd" =~ (export\ PATH=|export\ SHELL=|export\ BASH_ENV=) ]]; then
    _cs_type="env_manipulation"
    _cs_target="$_cs_cmd"
  fi

  # JSON-escape the command string (no jq dependency)
  local _cs_esc="$_cs_cmd"
  _cs_esc="${_cs_esc//\\/\\\\}"    # backslash
  _cs_esc="${_cs_esc//\"/\\\"}"    # double quote
  _cs_esc="${_cs_esc//$'\n'/\\n}"  # newline
  _cs_esc="${_cs_esc//$'\r'/\\r}"  # carriage return
  _cs_esc="${_cs_esc//$'\t'/\\t}"  # tab

  local _cs_pwd_esc="${PWD//\\/\\\\}"
  _cs_pwd_esc="${_cs_pwd_esc//\"/\\\"}"

  local _cs_target_esc="${_cs_target//\\/\\\\}"
  _cs_target_esc="${_cs_target_esc//\"/\\\"}"

  # Write JSONL record atomically (single echo, append mode)
  echo "{\"layer\":\"shell\",\"ts\":\"$_cs_ts\",\"pid\":$$,\"ppid\":$PPID,\"cwd\":\"$_cs_pwd_esc\",\"cmd\":\"$_cs_esc\",\"type\":\"$_cs_type\",\"target\":\"$_cs_target_esc\",\"exit\":$_cs_exit}" >> "$CLAWSIG_TRACE_FILE"

  return "$_cs_exit"
}

# ---- Activate: inherit trap into subshells ----
set -o functrace 2>/dev/null || true
set -o errtrace 2>/dev/null || true

# Bind the DEBUG trap
trap '_clawsig_debug_trap' DEBUG

# Lock the function to prevent tampering by the agent
readonly -f _clawsig_debug_trap 2>/dev/null || true
