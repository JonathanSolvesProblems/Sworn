#!/usr/bin/env bash
# SWORN installer for the SANS SIFT Workstation (Ubuntu 22.04 base).
# Idempotent: re-running upgrades. Does not modify evidence directories.

set -euo pipefail

SWORN_HOME="${SWORN_HOME:-$HOME/.sworn}"
VENV="$SWORN_HOME/venv"
KEYS_DIR="$SWORN_HOME/keys"
RULES_DIR="$SWORN_HOME/rules"
LOG="$SWORN_HOME/install.log"

log() { printf '[sworn-install] %s\n' "$*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }

main() {
  mkdir -p "$SWORN_HOME" "$KEYS_DIR" "$RULES_DIR"
  : > "$LOG"
  log "starting install at $(date -u)"

  detect_sift_or_warn
  ensure_python
  ensure_sift_tools  # presence check only; see comment in function
  create_venv_and_install
  init_keys
  install_symlink
  egress_rules_suggestion
  fetch_yara_rules_optional

  log ""
  log "SWORN install complete."
  log "  binary:        /usr/local/bin/sworn (or $VENV/bin/sworn)"
  log "  signing key:   $KEYS_DIR/host.ed25519.pem"
  log "  public key:    $KEYS_DIR/host.ed25519.pub.pem"
  log "  install log:   $LOG"
  log ""
  log "Try:  sworn --version"
  log "      sworn tools list"
  log "      sworn gateway --case-id DEMO --evidence /cases/example/disk.E01"
}

detect_sift_or_warn() {
  if [ -f /etc/sift-version ] || [ -d /etc/sift ]; then
    log "SIFT Workstation detected."
  else
    log "WARNING: not on a SIFT Workstation. Some tools may not be on PATH."
  fi
}

ensure_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 not found. SIFT 2025 ships Python 3.10+ by default."
  fi
  local v
  v="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
  case "$v" in
    3.10|3.11|3.12|3.13|3.14) log "python3 $v ok" ;;
    *) die "python3 $v unsupported (need 3.10+)";;
  esac
}

ensure_sift_tools() {
  # Presence check only; version verification is left to per-tool wrappers
  # so SWORN does not silently exclude a tool that ships a non-standard
  # --version flag on a given SIFT release.
  local missing=()
  for t in vol log2timeline.py psort.py EvtxECmd MFTECmd PECmd RECmd \
           hayabusa rip.pl yara fls icat mmls mactime bulk_extractor; do
    if ! command -v "$t" >/dev/null 2>&1; then
      missing+=("$t")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    log "tools missing from PATH: ${missing[*]}"
    log "SWORN will still install; missing tools will fail at call time and"
    log "the gateway will log the failure to actions.jsonl as you expect."
  else
    log "all expected SIFT tools present on PATH."
  fi
}

create_venv_and_install() {
  if [ ! -d "$VENV" ]; then
    log "creating venv at $VENV"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  pip install --upgrade pip wheel >>"$LOG" 2>&1
  log "installing sworn package"
  local repo_root
  repo_root="$(cd "$(dirname "$0")/.." && pwd)"
  pip install -e "$repo_root" >>"$LOG" 2>&1
  deactivate
}

init_keys() {
  local sk="$KEYS_DIR/host.ed25519.pem"
  if [ -f "$sk" ]; then
    log "signing key already present at $sk"
    return
  fi
  log "generating Ed25519 signing key at $sk"
  "$VENV/bin/sworn" init-keys --path "$sk" >>"$LOG" 2>&1
  chmod 600 "$sk"
}

install_symlink() {
  local target=/usr/local/bin/sworn
  if [ -L "$target" ] || [ -e "$target" ]; then
    return
  fi
  if [ -w /usr/local/bin ]; then
    ln -s "$VENV/bin/sworn" "$target"
    log "symlinked $target -> $VENV/bin/sworn"
  else
    log "skipping /usr/local/bin/ symlink (no write permission). "
    log "Run: sudo ln -s $VENV/bin/sworn /usr/local/bin/sworn"
  fi
}

egress_rules_suggestion() {
  if command -v nft >/dev/null 2>&1; then
    log "nftables available. To install SWORN egress rules manually:"
    log "  sudo nft add table inet sworn"
    log "  sudo nft add chain inet sworn output { type filter hook output priority 0\\; policy drop\\; }"
    log "  sudo nft add rule inet sworn output ct state established,related accept"
    log "  sudo nft add rule inet sworn output oifname \"lo\" accept"
    log "  sudo nft add rule inet sworn output ip daddr <LLM_PROVIDER_RANGE> accept"
    log "Skipping automatic install to avoid breaking your network."
  fi
}

fetch_yara_rules_optional() {
  if [ "${SWORN_FETCH_YARA:-0}" != "1" ]; then
    log "set SWORN_FETCH_YARA=1 to fetch Florian Roth signature-base"
    log "(CC BY-NC 4.0 license, hosted at github.com/Neo23x0/signature-base)."
    return
  fi
  if [ -d "$RULES_DIR/signature-base" ]; then
    log "YARA rules already fetched at $RULES_DIR/signature-base"
    return
  fi
  command -v git >/dev/null 2>&1 || die "git required for YARA rule fetch"
  log "cloning signature-base into $RULES_DIR/signature-base"
  git clone --depth=1 https://github.com/Neo23x0/signature-base.git \
    "$RULES_DIR/signature-base" >>"$LOG" 2>&1
}

main "$@"
