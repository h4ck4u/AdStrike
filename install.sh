#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AdStrike v5.0 «AdStrike» — Installer
# Tested on Kali Linux 2024+ / Parrot OS
# AUTHORISED PENETRATION TESTING ONLY
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'; PNK='\033[38;5;201m'
CYN='\033[96m'; DIM='\033[2m';  RST='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ADSTRIKE_VENV_DIR:-$SCRIPT_DIR/venv}"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
TOOLS_DIR="$SCRIPT_DIR/tools"
BIN_DIR="$TOOLS_DIR/bin"
LOCAL_TOOLS_SOURCE="${ADSTRIKE_LOCAL_TOOLS_SOURCE:-/home/kali/Desktop/ADRedTeam/tools}"
export PATH="$BIN_DIR:$PATH"

banner() {
    echo -e "${PNK}${BOLD}"
    echo "     ___       __   _____ __       _ __       "
    echo "    /   | ____/ /  / ___// /______(_) /_____ "
    echo "   / /| |/ __  /   \\__ \\/ __/ ___/ / //_/ _ \\"
    echo "  / ___ / /_/ /   ___/ / /_/ /  / / ,< /  __/"
    echo " /_/  |_\\__,_/   /____/\\__/_/  /_/_/|_|\\___/ "
    echo -e "${RST}"
    echo -e "  ${CYN}${BOLD}AdStrike v5.0 — Installer${RST}  ${DIM}56 modules · 8 kill-chain phases${RST}"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────${RST}"
    echo
}

step() { echo -e "\n  ${CYN}[*]${RST} ${BOLD}$*${RST}"; }
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
die()  { echo -e "  ${RED}[-]${RST} $* — aborting"; exit 1; }

clone_or_update() {
    local url="$1"
    local dest="$2"
    local name="$3"

    if [[ -d "$dest/.git" ]]; then
        git -C "$dest" pull --ff-only >/dev/null 2>&1 \
            && ok "$name updated" \
            || warn "$name update failed — keeping existing copy"
        return
    fi

    if [[ -e "$dest" ]]; then
        ok "$name already present"
        return
    fi

    git clone -q "$url" "$dest" \
        && ok "$name cloned to ${dest#$SCRIPT_DIR/}" \
        || warn "$name clone failed"
}

copy_local_tool_dir() {
    local name="$1"
    local src="$LOCAL_TOOLS_SOURCE/$name"
    local dest="$TOOLS_DIR/$name"

    [[ -d "$src" ]] || return 0
    if [[ -e "$dest" ]]; then
        cp -an "$src/." "$dest/" 2>/dev/null \
            && ok "$name already present; missing local files synced" \
            || ok "$name already present"
        return 0
    fi

    cp -a "$src" "$dest" \
        && ok "$name copied from $LOCAL_TOOLS_SOURCE" \
        || warn "$name copy failed from $LOCAL_TOOLS_SOURCE"
}

copy_local_bin_tool() {
    local name="$1"
    local src="$LOCAL_TOOLS_SOURCE/bin/$name"
    local dest="$BIN_DIR/$name"

    [[ -f "$src" ]] || return 0
    if [[ -e "$dest" || -L "$dest" ]]; then
        ok "tools/bin/$name already present"
        return 0
    fi

    cp -a "$src" "$dest" \
        && ok "tools/bin/$name copied from local source" \
        || warn "tools/bin/$name copy failed from $LOCAL_TOOLS_SOURCE/bin"
    chmod +x "$dest" 2>/dev/null || true
}

link_tool() {
    local src="$1"
    local name="$2"
    [[ -f "$src" ]] || return 0

    mkdir -p "$BIN_DIR"
    ln -sf "$src" "$BIN_DIR/$name"
    chmod +x "$src" "$BIN_DIR/$name" 2>/dev/null || true
    ok "tools/bin/$name linked"
}

banner

# Do not run the installer itself as root. It creates repo-local files such as
# venv/ and .env; root-owned artifacts break normal-user runs. The script
# uses sudo only for system package installation.
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    die "Do not run install.sh with sudo. Run: bash install.sh"
fi

# ── Python version check ──────────────────────────────────────────────────────
step "Checking Python version"
command -v python3 &>/dev/null || die "python3 not found"
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
(( PY_MINOR >= 10 )) || die "Python $PY_VER detected — requires 3.10+"
ok "Python $PY_VER"

# ── APT — install system packages ────────────────────────────────────────────
step "Installing system packages"
sudo apt-get update -qq 2>/dev/null || warn "apt update had warnings — continuing"

APT_PKGS=(
    impacket-scripts crackmapexec evil-winrm
    bloodhound bloodhound-python
    ldap-utils smbclient enum4linux-ng
    hashcat john hydra
    nmap masscan nbtscan netdiscover
    responder
    krb5-user dnsutils samba-common-bin
    net-tools git wget curl zip unzip
    python3-pip python3-venv python3-dev
)

sudo apt-get install -y -qq "${APT_PKGS[@]}" 2>/dev/null \
    && ok "System packages installed" \
    || warn "Some apt packages failed — check manually"

# ── Python virtual environment ────────────────────────────────────────────────
step "Setting up virtual environment → ${VENV_DIR#$SCRIPT_DIR/}"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "venv created"
else
    ok "venv already exists"
fi

VENV_PY="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PY" ]] || ! "$VENV_PY" -c 'import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix else 1)' >/dev/null 2>&1; then
    warn "${VENV_DIR#$SCRIPT_DIR/} is broken or not isolated — recreating it"
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
    VENV_PY="$VENV_DIR/bin/python"
    ok "venv recreated"
fi

PIP_CMD=("$VENV_PY" -m pip)

if ! "${PIP_CMD[@]}" --version >/dev/null 2>&1; then
    warn "pip module missing in ${VENV_DIR#$SCRIPT_DIR/} — bootstrapping with ensurepip"
    "$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 \
        || die "Could not bootstrap pip inside ${VENV_DIR#$SCRIPT_DIR/}"
fi

if [[ -f "$VENV_DIR/bin/pip" ]] && ! head -n 1 "$VENV_DIR/bin/pip" | grep -Fq "$VENV_DIR"; then
    warn "pip entrypoint points outside this repo — repairing ${VENV_DIR#$SCRIPT_DIR/}/bin/pip"
    "${PIP_CMD[@]}" install -q --force-reinstall pip \
        || die "Could not repair pip entrypoint inside ${VENV_DIR#$SCRIPT_DIR/}"
fi

step "Upgrading pip / setuptools / wheel"
"${PIP_CMD[@]}" install -q --upgrade pip setuptools wheel && ok "pip upgraded"

step "Installing Python dependencies"
[[ -f "$REQ_FILE" ]] && "${PIP_CMD[@]}" install -q -r "$REQ_FILE" && ok "requirements.txt installed"

step "Installing extra pip-only tools"
for pkg in netexec certipy-ad bloodhound mitm6 lsassy dploot roadrecon roadtx coercer ldap3; do
    "${PIP_CMD[@]}" install -q "$pkg" 2>/dev/null && ok "$pkg" \
        || warn "$pkg failed — may already be installed system-wide"
done

# ── Repo-local helper tools ───────────────────────────────────────────────────
step "Installing repo-local helper tools"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"

if [[ -d "$LOCAL_TOOLS_SOURCE" ]]; then
    ok "Local tool source found: $LOCAL_TOOLS_SOURCE"
    copy_local_tool_dir "krbrelayx"
    copy_local_tool_dir "PetitPotam"
    copy_local_tool_dir "ADExplorerSnapshot.py"

    for helper in \
        ADExplorerSnapshot.py dnstool.py gMSADumper.py gmsa_grant_and_dump.py \
        PetitPotam.py printerbug.py
    do
        copy_local_bin_tool "$helper"
    done
else
    warn "Local tool source not found: $LOCAL_TOOLS_SOURCE"
    warn "Set ADSTRIKE_LOCAL_TOOLS_SOURCE=/path/to/tools to use a different local source"
fi

if command -v git &>/dev/null; then
    clone_or_update "https://github.com/dirkjanm/krbrelayx" "$TOOLS_DIR/krbrelayx" "krbrelayx"
    clone_or_update "https://github.com/topotam/PetitPotam" "$TOOLS_DIR/PetitPotam" "PetitPotam"
    clone_or_update "https://github.com/c3c/ADExplorerSnapshot.py" "$TOOLS_DIR/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"
else
    warn "git not found — skipping GitHub helper tool clones"
fi

link_tool "$TOOLS_DIR/krbrelayx/dnstool.py" "dnstool.py"
link_tool "$TOOLS_DIR/krbrelayx/printerbug.py" "printerbug.py"
link_tool "$TOOLS_DIR/PetitPotam/PetitPotam.py" "PetitPotam.py"
link_tool "$TOOLS_DIR/ADExplorerSnapshot.py/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"

[[ -f "$TOOLS_DIR/krbrelayx/dnstool.py" ]] && ln -sf "$TOOLS_DIR/krbrelayx/dnstool.py" "$TOOLS_DIR/dnstool.py"
[[ -f "$TOOLS_DIR/krbrelayx/printerbug.py" ]] && ln -sf "$TOOLS_DIR/krbrelayx/printerbug.py" "$TOOLS_DIR/printerbug.py"
[[ -f "$TOOLS_DIR/PetitPotam/PetitPotam.py" ]] && ln -sf "$TOOLS_DIR/PetitPotam/PetitPotam.py" "$TOOLS_DIR/PetitPotam.py"

if [[ -f "$BIN_DIR/dnstool.py" || -f "$TOOLS_DIR/krbrelayx/dnstool.py" || -f /opt/krbrelayx/dnstool.py ]] || command -v dnstool.py &>/dev/null; then
    ok "dnstool.py available"
else
    warn "dnstool.py missing — ADIDNS write actions may fail"
fi

# ── Fix nxc impacket import (regsecrets.py missing from pip impacket) ────────
step "Fixing impacket/nxc version compatibility"
# System nxc was built against system impacket which has gkdi.py, dpapi_ng.py,
# WIN_VERSIONS etc. The pip-installed impacket (0.14.0) is missing these.
# The _nxc() agent wrapper sets PYTHONPATH to use system impacket for nxc calls.
# As a belt-and-suspenders fix, also copy the missing files to pip impacket.
PIP_IMP=$("$VENV_PY" -c "import impacket, os; print(os.path.dirname(impacket.__file__))" 2>/dev/null || true)
SYS_IMP="/usr/lib/python3/dist-packages/impacket"
if [[ -n "$PIP_IMP" && -d "$SYS_IMP" ]]; then
    copied=0
    for f in dpapi_ng.py msada_guids.py regsecrets.py; do
        if [[ -f "$SYS_IMP/$f" && ! -f "$PIP_IMP/$f" ]]; then
            cp "$SYS_IMP/$f" "$PIP_IMP/$f" && ((copied++)) || true
        fi
    done
    for f in gkdi.py icpr.py tsts.py; do
        if [[ -f "$SYS_IMP/dcerpc/v5/$f" && ! -f "$PIP_IMP/dcerpc/v5/$f" ]]; then
            cp "$SYS_IMP/dcerpc/v5/$f" "$PIP_IMP/dcerpc/v5/$f" && ((copied++)) || true
        fi
    done
    # Always overwrite utils.py — system version has parse_identity needed by getTGT.py
    if [[ -f "$SYS_IMP/examples/utils.py" ]]; then
        cp "$SYS_IMP/examples/utils.py" "$PIP_IMP/examples/utils.py" && ((copied++)) || true
    fi
    ok "impacket compatibility: $copied missing files synced from system to pip"
else
    warn "Could not sync impacket files — nxc ldap may have import errors"
    warn "Workaround: the agent uses PYTHONPATH fix automatically"
fi

# ── kerbrute ─────────────────────────────────────────────────────────────────
step "Checking kerbrute"
if command -v kerbrute &>/dev/null; then
    ok "kerbrute found in PATH"
else
    warn "kerbrute not found — install manually:"
    echo -e "  ${DIM}https://github.com/ropnop/kerbrute/releases${RST}"
    echo -e "  ${DIM}sudo install -m 755 kerbrute_linux_amd64 /usr/local/bin/kerbrute${RST}"
fi

# ── .env setup ────────────────────────────────────────────────────────────────
step "Setting up .env"
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        ok ".env created from template — edit with your engagement details"
    else
        touch "$SCRIPT_DIR/.env"
        ok ".env.example not found — created empty .env"
    fi
else
    ok ".env already exists"
fi

mkdir -p "$SCRIPT_DIR/output"

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo -e "  ${RED}──────────────────────────────────────────────────────────────────${RST}"
echo -e "  ${GRN}${BOLD} Installation complete!${RST}"
echo -e "  ${RED}──────────────────────────────────────────────────────────────────${RST}"
echo
echo -e "  ${CYN}Run:${RST}  ${BOLD}bash run.sh${RST}  or  ${BOLD}source ${VENV_DIR#$SCRIPT_DIR/}/bin/activate && python main.py${RST}"
echo -e "  ${DIM}Pip:${RST}  ${BOLD}$VENV_PY -m pip${RST}  ${DIM}(safe even if the repo path changes)${RST}"
echo -e "  ${DIM}Repo-local helper tools are available under tools/ and tools/bin/.${RST}"
echo -e "  ${DIM}For authorised penetration testing only.${RST}"
echo
