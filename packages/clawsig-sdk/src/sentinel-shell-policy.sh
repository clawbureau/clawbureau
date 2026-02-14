#!/usr/bin/env bash
#
# Clawsig Sentinel Shell Policy Evaluator
#
# Pure-bash real-time WPC policy enforcement. Sourced via BASH_ENV
# alongside sentinel-shell.sh. Provides evaluate_command() that
# pattern-matches against dangerous command patterns and a compiled
# policy file. Under 1ms per call. No forks, no subshells in hot path.
#
# Reads policy from .clawsig/policy.compiled (line-based format
# compiled from policy.json by compile-policy.ts).
#
# Policy format:
#   DENY_CMD:<glob>     — Block commands matching this glob
#   ALLOW_CMD:<glob>    — Exception: allow even if a DENY matches
#   DENY_FILE:<glob>    — Block commands that reference this file glob

# ---- Guard: prevent double-load ----
if [[ -n "$__CLAWSIG_POLICY_LOADED" ]]; then
  return 0 2>/dev/null || exit 0
fi
export __CLAWSIG_POLICY_LOADED="1"

# ---- Policy arrays (populated once at load time) ----
_CLAWSIG_DENY_CMDS=()
_CLAWSIG_ALLOW_CMDS=()
_CLAWSIG_DENY_FILES=()
_CLAWSIG_POLICY_FILE="${CLAWSIG_POLICY_FILE:-$PWD/.clawsig/policy.compiled}"
_CLAWSIG_POLICY_INIT=0

# ---- Load policy file into arrays (once) ----
_clawsig_load_policy() {
  if [[ "$_CLAWSIG_POLICY_INIT" -eq 1 ]]; then return; fi
  _CLAWSIG_POLICY_INIT=1

  if [[ -f "$_CLAWSIG_POLICY_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" == \#* ]] && continue

      if [[ "$line" == DENY_CMD:* ]]; then
        _CLAWSIG_DENY_CMDS+=("${line#DENY_CMD:}")
      elif [[ "$line" == ALLOW_CMD:* ]]; then
        _CLAWSIG_ALLOW_CMDS+=("${line#ALLOW_CMD:}")
      elif [[ "$line" == DENY_FILE:* ]]; then
        _CLAWSIG_DENY_FILES+=("${line#DENY_FILE:}")
      fi
    done < "$_CLAWSIG_POLICY_FILE"
  fi

  # Hardcoded baseline: always block the most dangerous patterns
  _CLAWSIG_DENY_CMDS+=("*curl*-X*POST*-d*@*/.ssh/*")
  _CLAWSIG_DENY_CMDS+=("*curl*-X*POST*-d*@*id_rsa*")
  _CLAWSIG_DENY_CMDS+=("*curl*-d*@*id_ed25519*")
  _CLAWSIG_DENY_CMDS+=("*curl*--data-binary*@*/.ssh/*")
  _CLAWSIG_DENY_CMDS+=("*wget*--post-file*/.ssh/*")
}

# ---- Evaluate a command against loaded policy ----
# Uses a global variable instead of echo to avoid subshell fork.
# Caller reads _CLAWSIG_EVAL_RESULT after calling.
_CLAWSIG_EVAL_RESULT="ALLOW"

evaluate_command() {
  _CLAWSIG_EVAL_RESULT="ALLOW"
  local cmd="$1"

  # Lazy-load policy on first call
  _clawsig_load_policy

  # Check DENY_FILE patterns first
  for pat in "${_CLAWSIG_DENY_FILES[@]}"; do
    # shellcheck disable=SC2053
    if [[ "$cmd" == $pat ]]; then
      _CLAWSIG_EVAL_RESULT="BLOCK"
      return 0
    fi
  done

  # Check DENY_CMD patterns with ALLOW_CMD exceptions
  for deny_pat in "${_CLAWSIG_DENY_CMDS[@]}"; do
    # shellcheck disable=SC2053
    if [[ "$cmd" == $deny_pat ]]; then
      # Check if any ALLOW rule overrides this DENY
      local is_allowed=0
      for allow_pat in "${_CLAWSIG_ALLOW_CMDS[@]}"; do
        # shellcheck disable=SC2053
        if [[ "$cmd" == $allow_pat ]]; then
          is_allowed=1
          break
        fi
      done

      if [[ "$is_allowed" -eq 0 ]]; then
        _CLAWSIG_EVAL_RESULT="BLOCK"
        return 0
      fi
    fi
  done

  return 0
}
