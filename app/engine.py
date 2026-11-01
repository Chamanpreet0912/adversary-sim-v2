"""Simulation engine. Nothing here executes real attacks: each technique only
emits a synthetic telemetry event that detection rules are evaluated against."""
TACTICS = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
           "Credential Access","Discovery","Lateral Movement","Exfiltration","Impact"]
T = lambda i,n,t,e: dict(id=i,name=n,tactic=t,event=e)
TECHNIQUES = {x["id"]:x for x in [
 T("T1566","Phishing","Initial Access","mail.attachment_opened"),
 T("T1190","Exploit Public-Facing App","Initial Access","web.exploit_pattern"),
 T("T1059","Command & Scripting Interpreter","Execution","proc.office_child_shell"),
 T("T1053","Scheduled Task/Job","Persistence","sched.task_created"),
 T("T1547","Boot/Logon Autostart","Persistence","reg.run_key_set"),
 T("T1068","Exploitation for Privilege Escalation","Privilege Escalation","proc.token_elevation"),
 T("T1562","Impair Defenses","Defense Evasion","av.service_stopped"),
 T("T1070","Indicator Removal","Defense Evasion","log.audit_cleared"),
 T("T1110","Brute Force","Credential Access","auth.failed_burst"),
 T("T1003","OS Credential Dumping","Credential Access","proc.lsass_access"),
 T("T1082","System Information Discovery","Discovery","proc.sysinfo_enum"),
 T("T1021","Remote Services","Lateral Movement","net.smb_rdp_login"),
 T("T1041","Exfiltration Over C2","Exfiltration","net.beacon_upload"),
 T("T1486","Data Encrypted for Impact","Impact","fs.mass_rename")]}
PROFILES = {
 "ransomware-crew":dict(name="Ransomware crew",steps=["T1566","T1059","T1053","T1562","T1003","T1021","T1486"]),
 "credential-thief":dict(name="Credential thief",steps=["T1190","T1110","T1003","T1082","T1021","T1041"]),
 "malicious-insider":dict(name="Malicious insider",steps=["T1082","T1547","T1068","T1070","T1041"])}
RULES = [  # id, title, covers, enabled by default
 ("R1","Office app spawns shell",["T1566","T1059"],True),
 ("R2","Failed-login burst",["T1110"],True),
 ("R3","LSASS memory access",["T1003"],True),
 ("R4","New scheduled task",["T1053"],False),
 ("R5","Mass file rename",["T1486"],False),
 ("R6","Audit log cleared",["T1070"],True),
 ("R7","Periodic outbound beacon",["T1041"],False),
 ("R8","WAF exploit signature",["T1190"],True),
 ("R9","Unusual SMB/RDP logon",["T1021"],False),
 ("R10","Security tool tampering",["T1562"],False)]

def simulate(profile_id, target, enabled_rules):
    p = PROFILES[profile_id]; steps = []
    for n, tid in enumerate(p["steps"]):
        t = TECHNIQUES[tid]
        hit = [r for r,_,cov,_ in RULES if r in enabled_rules and tid in cov]
        steps.append(dict(seq=n+1, technique=tid, name=t["name"], tactic=t["tactic"],
            event=t["event"], target=target, detected=bool(hit), rules=hit,
            note=("Alert raised by "+", ".join(hit)) if hit else
                 ("Rule exists but is disabled" if any(tid in c for _,_,c,_ in RULES) else "No detection rule exists")))
    d = sum(s["detected"] for s in steps)
    return dict(profile=profile_id, target=target, steps=steps, detected=d, total=len(steps),
                score=round(100*d/len(steps)))

def report_md(run):
    L = [f"# Attack Simulation Report #{run['id']}",
         f"**Adversary:** {PROFILES[run['profile']]['name']}  \n**Target:** {run['target']}  \n**Detection score:** {run['score']}% ({run['detected']}/{run['total']})\n",
         "| # | Tactic | Technique | Result | Note |","|---|---|---|---|---|"]
    for s in run["steps"]:
        L.append(f"| {s['seq']} | {s['tactic']} | {s['technique']} {s['name']} | {'Detected' if s['detected'] else 'MISSED'} | {s['note']} |")
    gaps = [s for s in run["steps"] if not s["detected"]]
    L.append("\n## Recommendations")
    L += [f"- **{s['technique']} {s['name']}**: {'enable the existing rule' if 'disabled' in s['note'] else 'write a new detection for ' + s['event']} (MITRE ATT&CK {s['technique']})." for s in gaps] or ["- No gaps found."]
    return "\n".join(L)
