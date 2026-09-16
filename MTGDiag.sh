#!/usr/bin/env bash
# Microsoft Tunnel Intelligent Readiness & Diagnostics
# Owners: Anushka Rai and Yeswanth Kumar
set -Eeuo pipefail
IFS=$'\n\t'; umask 077
VERSION="7.4.7"
READY_URL="https://aka.ms/microsofttunnelready"
UPGRADE_URL="https://learn.microsoft.com/en-us/intune/device-security/microsoft-tunnel/upgrade#microsoft-tunnel-update-history"
MODE=""; SCENARIO=""; EXECUTE=0; INTERNAL_URL=""; TIMEOUT=8; MAX_ENDPOINTS=0; LOG_SINCE="-4 hours"; OUT=""; MONITOR_SECONDS=300; CAPTURE_INTERFACE="any"; CAPTURE_FILTER="port 443"; NON_INTERACTIVE=0; FORCE_COLOR=0; DISABLE_COLOR=0; HEALTH_WAIT_SECONDS=180
AGENT=/etc/mstunnel/AgentSettings.json; ADMIN=/etc/mstunnel/admin-settings.json; OCS=/etc/mstunnel/ocserv.conf; IMAGES=/etc/mstunnel/images_configured; VER=/etc/mstunnel/version-info.json; INBOX=/etc/mstunnel/messages/in
usage(){ cat <<'EOF'
Microsoft Tunnel Intelligent Readiness & Diagnostics v7.4.7
Usage: sudo ./MTGDiag.sh [options]

Modes:
  --mode full|inventory|connectivity|internal|troubleshoot|preview-all|self-test
  --mode security-inventory   Read-only package inventory: host and Tunnel containers
  --mode security-updates     Preview selected Ubuntu 24.04 host package updates
  --mode log-collection       Collect host/container state and bounded recent logs
  --scenario unhealthy|ip-starvation|bridge-conflict|container-down|upgrade|network-trace
  --all-endpoints            Test all discovered endpoints
  --max-endpoints N          Smoke-test limit; 0 means all
  --internal-url URL         Exact internal access-check URL
  --timeout N                Network timeout, default 8
  --log-since TEXT           Default "-4 hours"
  --output-dir PATH
  --execute                  Permit guarded remediation after typed approval
  --monitor-seconds N        Default 300
  --health-wait-seconds N    Wait for starting containers, default 180
  --capture-interface NAME   Default any
  --capture-filter FILTER    Default "port 443"
  --force-color             Force ANSI colors when terminal detection is unavailable
  --no-color                Disable ANSI colors
  --non-interactive
  --help | --version

No --mode or --scenario opens the main menu.
security-inventory makes no network requests, installs nothing, and never remediates.
It records package revisions and system-interpreter PyJWT metadata, not CVE clearance.
security-updates uses cached APT metadata by default. --execute requires an interactive
terminal and separate typed approvals for metadata refresh and package installation.
Package updates can restart services. No automatic reboot or container package changes.
log-collection never remediates and does not probe network endpoints.
EOF
}
while (($#));do case "$1" in
 --mode)MODE="${2:-}";shift 2;; --preview-all)MODE=preview-all;EXECUTE=0;shift;; --scenario)SCENARIO="${2:-}";shift 2;; --execute)EXECUTE=1;shift;;
 --all-endpoints)MAX_ENDPOINTS=0;shift;; --max-endpoints)MAX_ENDPOINTS="${2:-}";shift 2;; --internal-url)INTERNAL_URL="${2:-}";shift 2;;
 --timeout)TIMEOUT="${2:-}";shift 2;; --log-since)LOG_SINCE="${2:-}";shift 2;; --output-dir)OUT="${2:-}";shift 2;;
 --monitor-seconds)MONITOR_SECONDS="${2:-}";shift 2;; --health-wait-seconds)HEALTH_WAIT_SECONDS="${2:-}";shift 2;; --capture-interface)CAPTURE_INTERFACE="${2:-}";shift 2;; --capture-filter)CAPTURE_FILTER="${2:-}";shift 2;;
 --force-color)FORCE_COLOR=1;shift;; --no-color)DISABLE_COLOR=1;shift;; --non-interactive)NON_INTERACTIVE=1;shift;; --help|-h)usage;exit 0;; --version)echo "$VERSION";exit 0;; *)echo "Unknown option: $1" >&2;usage;exit 2;;esac;done
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ && "$MAX_ENDPOINTS" =~ ^[0-9]+$ && "$MONITOR_SECONDS" =~ ^[1-9][0-9]*$ && "$HEALTH_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]]||{ echo "Invalid numeric option" >&2;exit 2; }
[[ $EUID -eq 0 ]]||{ echo "Run with sudo/root." >&2;exit 2; }
have(){ command -v "$1" >/dev/null 2>&1; }
# Detect terminal BEFORE stdout is routed through tee. --force-color can override
# terminal detection for SSH wrappers; --no-color/NO_COLOR disables ANSI output.
COLOR_MODE="auto"
[[ $FORCE_COLOR -eq 1 ]] && COLOR_MODE=force
[[ $DISABLE_COLOR -eq 1 || -n "${NO_COLOR:-}" ]] && COLOR_MODE=off
if [[ "$COLOR_MODE" == force || ( "$COLOR_MODE" == auto && -t 1 ) ]]; then COLOR_ENABLED=1; else COLOR_ENABLED=0; fi
TS="$(date -u +%Y%m%dT%H%M%SZ)";OUT="${OUT:-/tmp/mtgdiag-$TS}";[[ ! -e "$OUT"||-z "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]||{ echo "Output directory is not empty: $OUT" >&2;exit 3;};mkdir -p "$OUT";chmod 700 "$OUT";REPORT="$OUT/report.txt";RESULTS="$OUT/results.jsonl";:>"$REPORT";:>"$RESULTS"
if [[ $COLOR_ENABLED -eq 1 ]]; then
 C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'; C_PURPLE=$'\033[35m'; C_BOLD=$'\033[1m'
else
 C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_PURPLE=""; C_BOLD=""
fi
# Keep the saved report ANSI-free while the terminal gets color.
exec 3>>"$REPORT"
status_color(){ case "$1" in PASS)printf %s "$C_GREEN";;FAIL)printf %s "$C_RED";;REVIEW|SKIP)printf %s "$C_YELLOW";;ACTION)printf %s "$C_PURPLE";;INFO)printf %s "$C_BLUE";;*)printf %s "$C_RESET";;esac; }
pass(){ emit PASS "$1" "$2";};fail(){ emit FAIL "$1" "$2";};info(){ emit INFO "$1" "$2";};review(){ emit REVIEW "$1" "$2";};action(){ emit ACTION "$1" "$2";};skip(){ emit SKIP "$1" "$2";}
emit(){ local s="$1" i="$2" m="$3" c;c="$(status_color "$s")";printf '%s[%s]%s %s%s:%s %s\n' "$c" "$s" "$C_RESET" "$C_BOLD" "$i" "$C_RESET" "$m";printf '[%s] %s: %s\n' "$s" "$i" "$m" >&3;python3 - "$RESULTS" "$s" "$i" "$m" <<'PY'
import json,sys,datetime,os
p,s,i,m=sys.argv[1:]
stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
open(p,'a').write(json.dumps({'status':s,'id':i,'message':m,'time':stamp})+'\n')
if os.environ.get('MTGDIAG_PROGRESS') == '1':
    event=json.dumps({'status':s,'check':i,'target':'','message':m,'time':stamp})
    path=os.environ.get('MTGDIAG_PROGRESS_FILE')
    if path:
        with open(path,'a',encoding='utf-8') as stream: stream.write(event+'\n')
    else: print('MTG_PROGRESS '+event, flush=True)
PY
}
progress(){
 [[ "${MTGDIAG_PROGRESS:-0}" == 1 ]]&&have python3||return 0
 python3 - "$1" "$2" "$3" "$4" <<'PY'
import datetime,json,sys,os
status,check,target,message=sys.argv[1:]
event=json.dumps(dict(status=status,check=check,target=target,message=message,
    time=datetime.datetime.now(datetime.timezone.utc).isoformat()))
path=os.environ.get('MTGDIAG_PROGRESS_FILE')
if path:
    with open(path,'a',encoding='utf-8') as stream: stream.write(event+'\n')
else: print('MTG_PROGRESS '+event, flush=True)
PY
}
step(){ printf '[CHECK] %s | %s: %s\n' "$1" "$2" "$3";printf '[CHECK] %s | %s: %s\n' "$1" "$2" "$3" >&3;progress RUNNING "$1" "$2" "$3"; }
phase(){ printf '\n%s%s[PHASE]%s %s\n' "$C_PURPLE" "$C_BOLD" "$C_RESET" "$1";printf '\n[PHASE] %s\n' "$1" >&3;progress RUNNING PHASE host "$1"; }
declare -A DIAGNOSTIC_STATUS=()
# Reuse baseline results only; post-remediation checks call the diagnostic directly.
run_diagnostic(){
 local check="$1" rc
 if [[ -n "${DIAGNOSTIC_STATUS[$check]+set}" ]];then
  return "${DIAGNOSTIC_STATUS[$check]}"
 fi
 step "$check" host "Running diagnostic: ${check//_/ }"
 if "$check";then rc=0;else rc=$?;fi
 DIAGNOSTIC_STATUS["$check"]="$rc"
 return "$rc"
}
redact(){ sed -E 's#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1<REDACTED>@#g;s/([Aa]uthorization:[[:space:]]*(Bearer|Basic))[[:space:]]+[^[:space:]]+/\1 <REDACTED>/g;s/(secret|password|passwd)=([^[:space:]]+)/\1=<REDACTED>/Ig'; }
json_get(){ local f="$1" k="$2";[[ -r "$f" ]]||return 0;if have jq;then jq -r --arg k "$k" '.[$k]//empty' "$f" 2>/dev/null;else sed -nE 's/.*"'"$k"'"[[:space:]]*:[[:space:]]*"?([^",}]*)"?.*/\1/p' "$f"|head -1;fi; }
digest_get(){ grep -Eio "$2[^s]{0,120}sha256:[0-9a-f]{64}" "$1" 2>/dev/null|grep -Eo 'sha256:[0-9a-f]{64}'|head -1||true; }
conf_values(){ awk -F= -v k="$1" 'BEGIN{IGNORECASE=1}$1~"^[[:space:]]*"k"[[:space:]]*$"{v=$0;sub(/^[^=]*=[[:space:]]*/,"",v);print v}' "$OCS" 2>/dev/null||true; }
ENGINE=none;have podman&&ENGINE=podman;[[ "$ENGINE" == none ]]&&have docker&&ENGINE=docker
container_rows(){ [[ "$ENGINE" != none ]]&&"$ENGINE" ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null|grep -Ei 'mstunnel|ocserv'||true; }
TCPDUMP_PID="";stop_capture(){ if [[ -n "$TCPDUMP_PID" ]]&&kill -0 "$TCPDUMP_PID" 2>/dev/null;then kill -INT "$TCPDUMP_PID" 2>/dev/null||true;wait "$TCPDUMP_PID" 2>/dev/null||true;fi;TCPDUMP_PID="";};trap stop_capture EXIT INT TERM
start_capture(){ local f="$1";have tcpdump||{ fail TRACE "tcpdump unavailable";return 1;};tcpdump -i "$CAPTURE_INTERFACE" -U -w "$f" $CAPTURE_FILTER>"$OUT/tcpdump.log" 2>&1 & TCPDUMP_PID=$!;sleep 2;kill -0 "$TCPDUMP_PID" 2>/dev/null||{ fail TRACE "tcpdump failed to start";return 1;};pass TRACE "Capture started; PID=$TCPDUMP_PID; interface=$CAPTURE_INTERFACE; filter=$CAPTURE_FILTER"; }
package(){ stop_capture;step REPORT "$OUT/report.html" "Render the HTML report from collected findings";python3 - "$RESULTS" "$REPORT" "$OUT/report.html" "$VERSION" "$MODE" "$SCENARIO" "$TS" <<'PY'
import html
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from string import Template

j, t, output, version, mode, scenario, run_id = sys.argv[1:]
statuses = ("FAIL", "REVIEW", "ACTION", "SKIP", "PASS", "INFO")
attention_statuses = {"FAIL", "REVIEW", "ACTION"}
records, errors = [], []
with open(j, encoding="utf-8") as source:
    for number, line in enumerate(source, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"Line {number}: invalid JSON.")
            continue
        if (not isinstance(record, dict)
                or not all(isinstance(record.get(key), str) for key in ("status", "id", "message"))
                or record["status"] not in statuses):
            errors.append(f"Line {number}: invalid finding fields or unsupported status.")
            continue
        records.append(record)

counts = Counter(record["status"] for record in records)
attention = sum(counts[status] for status in attention_statuses)
if errors:
    title, tone, summary = "Report incomplete", "fail", "Some records could not be read. Review the report warning before drawing conclusions."
elif counts["FAIL"]:
    title, tone, summary = "Attention required", "fail", "Failure records were captured during this run. Start with the highlighted findings below."
elif attention:
    title, tone, summary = "Review recommended", "review", "Review items or proposed actions need attention. They are not all confirmed failures."
elif records:
    title, tone, summary = "No failures recorded", "pass", "No FAIL records were captured. Coverage gaps and untested conditions may still remain."
else:
    title, tone, summary = "No findings recorded", "info", "This run contains no diagnostic findings. No health assessment can be made."

escape = lambda value: html.escape(str(value), quote=True)
rows = []
# Keep every event once; rank by status while preserving order within each status.
for record in sorted(records, key=lambda item: statuses.index(item["status"])):
    status = record["status"]
    stamp = record.get("time", "")
    stamp = stamp if isinstance(stamp, str) else ""
    display_time = stamp
    if stamp:
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                display_time = parsed.astimezone(timezone.utc).strftime("%H:%M:%S UTC")
        except ValueError:
            pass
    timestamp = (f'<time datetime="{escape(stamp)}" title="{escape(stamp)}">{escape(display_time)}</time>'
                 if stamp else "")
    rows.append(
        f'<article class="finding {status.lower()}" data-status="{status}">'
        f'<div class="finding-status"><span class="badge {status.lower()}">{status}</span></div>'
        f'<div class="finding-content"><div class="finding-heading"><h3>{escape(record["id"])}</h3>'
        f'{timestamp}</div><p>{escape(record["message"])}</p></div></article>'
    )

metrics = []
for status, label, note, symbol in (
    ("FAIL", "Failures", "Recorded failure events", "!"),
    ("REVIEW", "To review", "Warnings & coverage gaps", "?"),
    ("ACTION", "Actions", "Proposed next steps", "+"),
    ("PASS", "Passed", "Recorded pass events", "OK"),
):
    metrics.append(
        f'<button type="button" class="metric {status.lower()}" data-filter="{status}" '
        f'aria-pressed="false" aria-controls="findings" disabled>'
        f'<span class="metric-top"><span>{label}</span><span class="metric-icon" aria-hidden="true">{symbol}</span></span>'
        f'<strong>{counts[status]}</strong><span class="metric-note">{note}</span></button>'
    )
filters = []
for value, label, count in (
    ("attention", "Needs attention", attention), ("all", "All findings", len(records)),
    ("FAIL", "Fail", counts["FAIL"]), ("REVIEW", "Review", counts["REVIEW"]),
    ("ACTION", "Action", counts["ACTION"]), ("PASS", "Pass", counts["PASS"]),
    ("INFO", "Info", counts["INFO"]), ("SKIP", "Skipped", counts["SKIP"]),
):
    filters.append(
        f'<button type="button" class="filter" data-filter="{value}" '
        f'aria-pressed="{"true" if value == "all" else "false"}" aria-controls="findings" disabled>'
        f'{label}<span>{count}</span></button>'
    )
warning = ""
if errors:
    warning = (
        '<aside class="report-warning" role="alert"><strong>Incomplete evidence</strong>'
        f'<p>{len(errors)} unreadable record(s) excluded from the counts. Check results.jsonl.</p>'
        '<details><summary>Show affected lines</summary><ul>'
        + "".join(f"<li>{escape(error)}</li>" for error in errors)
        + "</ul></details></aside>"
    )

page = Template(r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>$title | Microsoft Tunnel Diagnostics</title>
<style>
:root{--ink:#17253d;--muted:#52637b;--line:#dde4ee;--blue:#155eef;--fail:#b42318;--review:#945c00;--action:#6941c6;--pass:#067647}
*{box-sizing:border-box}body{margin:0;background:#f3f6fb;color:var(--ink);font:14px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--blue);text-underline-offset:3px}button,input{font:inherit}button{cursor:pointer}
button:focus-visible,a:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #155eef;outline-offset:4px}
button:disabled{cursor:default}button[hidden],[hidden]{display:none!important}
.shell{width:min(1200px,calc(100% - 64px));margin:0 auto}
.topbar{background:#fff;border-bottom:1px solid var(--line)}.topbar .shell{display:flex;justify-content:space-between;align-items:center;gap:20px;min-height:80px}
.brand{display:flex;align-items:center;gap:13px}.brand-mark{display:grid;grid-template-columns:repeat(2,8px);gap:3px;padding:12px;border-radius:12px;background:#eaf1ff}
.brand-mark i{width:8px;height:8px;background:#155eef;border-radius:2px}.brand strong{display:block;font-size:16px;letter-spacing:-.3px}
.brand small{display:block;color:var(--muted);font-size:11px;letter-spacing:1.5px;text-transform:uppercase}
.top-links{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.top-links a{padding:8px 13px;border:1px solid var(--line);border-radius:8px;text-decoration:none;font-weight:600;font-size:12px}
.top-links a:hover{background:#f3f6fb}.version{color:var(--muted);font-size:12px;margin-right:5px}
main{padding:32px 0 24px}.hero{position:relative;overflow:hidden;background:linear-gradient(115deg,#10213e,#1d365d);border:1px solid #2c4569;border-radius:18px;color:#fff;padding:30px 34px;box-shadow:0 8px 24px #11244410}
.hero-top{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.8px;color:#b9cbe7;font-weight:600}
.run-id{font:11px/1.5 Consolas,monospace;color:#b9cbe7;overflow-wrap:anywhere}
.hero h1{font-size:clamp(27px,4vw,38px);line-height:1.2;letter-spacing:-1.2px;margin:20px 0 10px}
.hero p{color:#d3dff1;max-width:750px;margin:0;font-size:14px}.hero-bottom{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:24px}
.hero-tag{font-size:12px;background:#ffffff0d;border:1px solid #ffffff30;border-radius:6px;padding:5px 10px;overflow-wrap:anywhere}
.hero-status{display:inline-flex;align-items:center;gap:7px}.hero-status:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.hero-status.fail{color:#ffb3ac}.hero-status.review{color:#ffd68b}.hero-status.pass{color:#9de8c3}.hero-status.info{color:#b8d5ff}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin:22px 0}
.metric{display:flex;flex-direction:column;text-align:left;border:1px solid var(--line);border-radius:12px;background:#fff;padding:19px 21px;color:var(--ink);box-shadow:0 2px 3px #17253d03}
.metric:not(:disabled):hover{border-color:#98accb;box-shadow:0 4px 12px #17253d0a}.metric[aria-pressed="true"]{outline:2px solid var(--blue);outline-offset:0}
.metric-top{display:flex;justify-content:space-between;align-items:center;gap:8px;width:100%;font-weight:600;color:var(--muted)}
.metric-icon{display:grid;place-items:center;width:28px;height:28px;border-radius:8px;font-size:13px;font-weight:700}
.metric strong{font-size:34px;line-height:1.2;letter-spacing:-1px;margin:10px 0 5px}.metric-note{font-size:11px;color:var(--muted)}
.metric.fail strong{color:var(--fail)}.metric.review strong{color:var(--review)}.metric.action strong{color:var(--action)}.metric.pass strong{color:var(--pass)}
.metric.fail .metric-icon{background:#feeceb;color:var(--fail)}.metric.review .metric-icon{background:#fff3d8;color:var(--review)}
.metric.action .metric-icon{background:#f0eaff;color:var(--action)}.metric.pass .metric-icon{background:#e5f6ed;color:var(--pass)}
.findings-panel{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 3px 12px #17253d03}
.panel-heading{padding:22px 24px 16px;display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.panel-heading h2{font-size:19px;letter-spacing:-.4px;margin:0 0 3px}.panel-heading p{font-size:12px;color:var(--muted);margin:0}
.total{white-space:nowrap;border:1px solid var(--line);border-radius:20px;padding:4px 10px;font-size:11px;color:var(--muted);background:#f8fafc}
.toolbar{padding:0 24px 18px;border-bottom:1px solid var(--line)}.search-row{display:flex;gap:10px;align-items:flex-end;margin-bottom:16px}
.search{flex:1}.search label{display:block;font-size:11px;font-weight:600;color:var(--muted);margin-bottom:5px}
.search input{width:100%;border:1px solid #cdd7e5;background:#f8fafc;color:var(--ink);padding:10px 13px;border-radius:8px}
.reset{padding:10px 14px;border:1px solid #cdd7e5;background:white;border-radius:8px;color:var(--ink);white-space:nowrap}
.filters{display:flex;gap:7px;flex-wrap:wrap}.filter{display:flex;align-items:center;gap:7px;padding:6px 11px;border-radius:7px;background:white;border:1px solid var(--line);color:var(--muted);font-size:12px;font-weight:600}
.filter span{font-size:10px;min-width:18px;text-align:center;background:#edf1f7;border-radius:4px;padding:0 4px;color:#52637b}
.filter[aria-pressed="true"]{color:#1748aa;border-color:#b3caff;background:#ecf3ff}.filter[aria-pressed="true"] span{background:#d8e7ff;color:#1748aa}
.results-bar{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;background:#f8fafc;border-bottom:1px solid var(--line);padding:10px 24px;color:var(--muted);font-size:11px}
.finding{display:flex;gap:18px;padding:20px 24px;border-bottom:1px solid #e8edf4;border-left:4px solid transparent}
.finding:last-child{border-bottom:0}.finding.fail{border-left-color:#e5484d;background:#fff6f5}.finding.review{border-left-color:#e0a332;background:#fffdf5}
.finding.action{border-left-color:#9871e4;background:#fcfaff}.finding-status{width:76px;flex-shrink:0;padding-top:1px}
.badge{display:inline-block;border:1px solid transparent;border-radius:5px;padding:3px 7px;font-size:10px;letter-spacing:.4px;font-weight:700}
.badge.fail{background:#fee4e2;border-color:#ffc9c4;color:#a61b12}.badge.review{background:#fff0cc;border-color:#f4d891;color:#805100}
.badge.action{background:#efe6ff;border-color:#dac4ff;color:#6036ae}.badge.pass{background:#e8f7ef;border-color:#c4e9d4;color:#06673f}
.badge.info{background:#eaf2ff;border-color:#d0e1fc;color:#265da0}.badge.skip{background:#eff2f6;border-color:#dce2ea;color:#526175}
.finding-content{min-width:0;flex:1}.finding-heading{display:flex;justify-content:space-between;gap:12px;align-items:baseline}
.finding h3{font:600 12px/1.6 Consolas,"SFMono-Regular",monospace;margin:0;overflow-wrap:anywhere}.finding time{color:var(--muted);font-size:10px;white-space:nowrap}
.finding p{margin:6px 0 0;color:#34445c;font-size:13px;white-space:pre-wrap;overflow-wrap:anywhere}
.empty{padding:40px 24px;text-align:center;color:var(--muted)}.empty strong{display:block;color:var(--ink);font-size:16px;margin-bottom:5px}
.report-warning{margin:20px 0;background:#fff3e8;border:1px solid #ebbf94;border-left:4px solid #bc610a;border-radius:9px;padding:16px 20px;color:#713c09}
.report-warning p{margin:4px 0}.report-warning summary{cursor:pointer}noscript{display:block;padding:12px 24px;background:#fff8e6;color:#805100}
.footer{display:flex;justify-content:space-between;gap:16px;margin:20px 0;color:var(--muted);font-size:11px}.footer p{margin:0;max-width:810px}
@media(max-width:760px){.shell{width:calc(100% - 28px)}.topbar .shell{padding:16px 0;align-items:flex-start;flex-direction:column;gap:12px}
main{padding-top:18px}.hero{padding:23px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.metric{padding:15px}
.panel-heading,.finding{padding:18px 16px}.toolbar{padding:0 16px 16px}.results-bar{padding:10px 16px}.finding{gap:12px}
.finding-heading{display:block}.finding time{display:block;margin-top:3px}.finding-status{width:66px}.footer{flex-direction:column}}
@media(max-width:380px){.search-row{flex-wrap:wrap}.search{flex-basis:100%}.hero h1{font-size:26px}.metric-note{font-size:10px}}
@media print{body{background:white}.shell{width:100%}.top-links,.toolbar,.metric,.empty,noscript{display:none!important}.metrics{display:none}
.hero{background:white;color:var(--ink);border:1px solid var(--line);box-shadow:none}.hero p,.eyebrow,.run-id,.hero-status,.hero-tag{color:var(--ink)!important}
.hero-tag{border-color:var(--line)}.findings-panel{box-shadow:none}.finding,.finding[hidden]{display:flex!important;break-inside:avoid}
.results-bar{display:none}.hero,.finding,.badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}.footer{display:block}}
</style>
</head>
<body>
<header class="topbar"><div class="shell">
<div class="brand"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span><div><strong>Microsoft Tunnel</strong><small>Diagnostics workspace</small></div></div>
<nav class="top-links" aria-label="Report exports"><span class="version">MTGDiag $version</span><a href="report.txt">Text report</a><a href="results.jsonl">Raw findings</a></nav>
</div></header>
<main class="shell">
<section class="hero" aria-labelledby="report-title"><div class="hero-top"><span class="eyebrow">Readiness &amp; diagnostics report</span><span class="run-id">RUN $run_id</span></div>
<h1 id="report-title">$title</h1><p>$summary</p>
<div class="hero-bottom"><span class="hero-tag hero-status $tone">$attention records need attention</span><span class="hero-tag">Mode: $mode</span><span class="hero-tag">Scenario: $scenario</span></div>
</section>
$warning
<section class="metrics" aria-label="Recorded finding counts">$metrics</section>
<section class="findings-panel" aria-labelledby="findings-title">
<div class="panel-heading"><div><h2 id="findings-title">Findings</h2><p>Problems first. Every recorded event appears once.</p></div><span class="total">$total recorded</span></div>
<div class="toolbar"><div class="search-row"><div class="search"><label for="search">Search findings</label><input id="search" type="search" placeholder="Search a check, package, endpoint or message..." autocomplete="off" aria-controls="findings" disabled></div><button class="reset" id="reset" type="button" disabled>Reset filters</button></div>
<div class="filters" role="group" aria-label="Filter by status">$filters</div></div>
<noscript>Interactive filters require JavaScript. All findings are shown below, with problems first.</noscript>
<div class="results-bar"><span id="result-count" role="status" aria-live="polite">$total of $total findings</span><span>Ordered by status, then original event order</span></div>
<div id="findings">$rows</div>
<div class="empty" id="empty"$empty_hidden><strong>$empty_title</strong><span>$empty_message</span></div>
</section>
<footer class="footer"><p>Counts describe recorded events, not unique vulnerabilities or final service state. Read event times and remediation results together. A passing check does not establish CVE clearance.</p><span>Self-contained report &middot; works offline</span></footer>
</main>
<script>
(function () {
  "use strict";
  const rows = Array.from(document.querySelectorAll(".finding"));
  const buttons = Array.from(document.querySelectorAll("[data-filter]"));
  const search = document.getElementById("search");
  const reset = document.getElementById("reset");
  const empty = document.getElementById("empty");
  const counter = document.getElementById("result-count");
  const attention = new Set(["FAIL", "REVIEW", "ACTION"]);
  let active = rows.some(function (row) { return attention.has(row.dataset.status); }) ? "attention" : "all";
  const searchable = rows.map(function (row) { return row.textContent.toLowerCase(); });
  function applyFilters() {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    rows.forEach(function (row, index) {
      const matchesStatus = active === "all" || row.dataset.status === active ||
        (active === "attention" && attention.has(row.dataset.status));
      row.hidden = !(matchesStatus && searchable[index].includes(query));
      if (!row.hidden) visible += 1;
    });
    buttons.forEach(function (button) { button.setAttribute("aria-pressed", String(button.dataset.filter === active)); });
    counter.textContent = visible + " of " + rows.length + " findings";
    empty.hidden = visible !== 0;
    if (rows.length) {
      empty.querySelector("strong").textContent = "No matching findings";
      empty.querySelector("span").textContent = "Try another status or reset your filters.";
    }
  }
  buttons.forEach(function (button) {
    button.disabled = false;
    button.addEventListener("click", function () { active = button.dataset.filter; applyFilters(); });
  });
  search.disabled = false;
  reset.disabled = false;
  search.addEventListener("input", applyFilters);
  reset.addEventListener("click", function () { active = "all"; search.value = ""; applyFilters(); search.focus(); });
  applyFilters();
}());
</script>
</body>
</html>''')
with open(output, "w", encoding="utf-8") as destination:
    destination.write(page.substitute(
        title=escape(title), summary=escape(summary), tone=tone, version=escape(version),
        run_id=escape(run_id), mode=escape(mode or "unspecified"), scenario=escape(scenario or "none"),
        attention=attention, warning=warning, metrics="".join(metrics), filters="".join(filters),
        total=len(records), rows="".join(rows), empty_hidden=" hidden" if records else "",
        empty_title="No findings recorded", empty_message="No diagnostic records were available for this run.",
    ))
PY
step EVIDENCE "$OUT" "Calculate SHA-256 checksums and create evidence.tar.gz"
if ! (cd "$OUT"&&find . -maxdepth 1 -type f ! -name evidence.tar.gz ! -name SHA256SUMS -print0|sort -z|xargs -0 sha256sum>SHA256SUMS);then fail EVIDENCE "Checksum generation failed";return 1;fi
local archive
archive=$(mktemp "${OUT%/}.archive.XXXXXXXX")||{ fail EVIDENCE "Could not create the temporary evidence archive";return 1;}
if ! tar -C "$OUT" -czf "$archive" --exclude evidence.tar.gz .;then rm -f -- "$archive";fail EVIDENCE "Evidence archive creation failed";return 1;fi
if ! mv -f -- "$archive" "$OUT/evidence.tar.gz";then rm -f -- "$archive";fail EVIDENCE "Could not save the evidence archive";return 1;fi
progress PASS EVIDENCE "$OUT/evidence.tar.gz" "HTML report, checksums and evidence archive created"
printf '\nReport: %s\nHTML: %s\nEvidence: %s\n' "$REPORT" "$OUT/report.html" "$OUT/evidence.tar.gz"; }
banner(){ printf '%s%s%s\n%s%s%s\n' "$C_BLUE" "================================================================================" "$C_RESET" "$C_BOLD" " MICROSOFT TUNNEL INTELLIGENT READINESS & DIAGNOSTICS" "$C_RESET"; printf '%s\n' " Version: $VERSION | Mode: ${MODE:-menu} | Scenario: ${SCENARIO:-none}" " Owners: Anushka Rai and Yeswanth Kumar" " Output: $OUT" "================================================================================"; }
preflight(){
 phase "Runtime prerequisites"
 local miss=0 c
 step PRECHECK host "Verify commands: bash, python3, curl, openssl, tar, awk, sed, grep, sort, find, sha256sum and timeout"
 for c in bash python3 curl openssl tar awk sed grep sort find sha256sum timeout;do
  if ! have "$c";then fail "PRE-$c" missing;miss=1;fi
 done
 [[ $miss -ne 0 ]]||pass PRECHECK "All runtime prerequisites available"
 return "$miss"
}
supportability(){ local ID VERSION_ID PRETTY_NAME VERSION;[[ -r /etc/os-release ]]&&. /etc/os-release||true;local ev mm st=FAIL reason="Unsupported or unlisted OS/engine pair";ev="$([[ "$ENGINE" != none ]]&&$ENGINE --version 2>/dev/null||echo unavailable)";mm="$(printf %s "${VERSION_ID:-}"|grep -Eo '^[0-9]+\.[0-9]+'||true)";if [[ "${ID:-}" == ubuntu&&"$ENGINE" == docker&&( "$mm" == 24.04||"$mm" == 26.04 ) ]];then st=PASS;reason="Ubuntu $mm with Docker detected";elif [[ "${ID:-}" =~ rhel|redhat&&"$ENGINE" == podman ]];then st=PASS;reason="RHEL $mm with Podman detected; verify exact published Podman row";fi;emit "$st" SUPPORT "$reason | OS=${PRETTY_NAME:-unknown} | Engine=$ev"; }
container_log_snapshot(){
 local id="$1" name="$2" label="$3" show_details="${4:-1}" driver logpath line source="none"
 local file="$OUT/container-$name-health.log"
 step "LOG-$name" "$name ($id)" "Inspect logging driver/path, then collect up to 80 timestamped lines with $ENGINE logs"
 driver="$($ENGINE inspect --format '{{.HostConfig.LogConfig.Type}}' "$id" 2>/dev/null || echo unknown)"
 logpath="$($ENGINE inspect --format '{{.LogPath}}' "$id" 2>/dev/null || true)"
 : > "$file"
 if "$ENGINE" logs --timestamps --tail 80 "$id" >"$file" 2>"$file.error";then
   source="$ENGINE logs"
 elif [[ -n "$logpath" && "$logpath" != '<no value>' && -r "$logpath" ]];then
   step "LOG-$name" "$logpath" "Container logs command failed; read the last 80 lines from the engine log file"
   tail -n 80 "$logpath" >"$file" 2>>"$file.error" || true;source="LogPath=$logpath"
 elif have journalctl;then
   step "LOG-$name" journalctl "Container logs unavailable; read Tunnel journal tags since $LOG_SINCE"
   journalctl --since "$LOG_SINCE" -t mstunnel_monitor -t mstunnel-agent -t ocserv --no-pager >"$file" 2>>"$file.error" || true;source="journalctl tags"
 fi
 if [[ -s "$file" ]];then
   progress INFO "LOG-$name" "$file" "Saved $(wc -l <"$file") lines using $source"
   if [[ $show_details -eq 1 ]];then
     info "LOG-$name" "$label | LoggingDriver=$driver | LogSource=$source | Relevant recent log lines:"
     while IFS= read -r line;do info "LOG-$name" "$line";done < <(grep -Ei 'starting|started|healthy|ready|checkup|upgrade|pull|download|connect|register|error|fail|warn|timeout|certificate|proxy|dns' "$file" | tail -n 12)
   fi
 else
   review "LOG-$name" "Container log content is empty or not locally readable with LoggingDriver=$driver. See $file.error and mst-cli status evidence"
 fi
}


containers_health(){
 phase "Container status and health"
 local start_epoch now elapsed waiting wait_targets id name status image health running role key final_bad=0 wait_announced=0
 local -A PREV=() FINAL=() IDS=() IMAGES_MAP=()
 start_epoch=$(date +%s)
 [[ "$ENGINE" != none ]]||{ fail CONTAINER "No container engine is available; container inspection was not run";return 1;}
 step CONTAINER "$ENGINE" "List Microsoft Tunnel/ocserv containers with ps -a and inspect their running/health state"
 while true;do
   waiting=0;wait_targets="";FINAL=();IDS=();IMAGES_MAP=()
   while IFS='|' read -r id name status image;do
     [[ -n "$id" ]]||continue;IDS["$name"]="$id";IMAGES_MAP["$name"]="$image"
     if [[ -z "${PREV[$name]+set}" ]];then step CONTAINER-INSPECT "$name ($id)" "Read $ENGINE inspect health; allow up to ${HEALTH_WAIT_SECONDS}s for starting containers";fi
     health="$($ENGINE inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-reported{{end}}' "$id" 2>/dev/null||echo unknown)"
     running=no;[[ "$status" =~ Up|running ]]&&running=yes
     # Status includes changing uptime; only identity and health define a transition.
     key="$id|$running|$health"
     if [[ "$running" == yes && "$health" == starting ]];then
       waiting=1
       wait_targets+="$name "
       if [[ $wait_announced -eq 0 ]];then
         info CONTAINER-WAIT "Waiting up to ${HEALTH_WAIT_SECONDS}s for starting containers; unchanged states are suppressed"
         wait_announced=1
       fi
       if [[ "${PREV[$name]:-}" != "$key" ]];then
         info "CONTAINER-$name-WAIT" "Name=$name | Health=starting"
       fi
     fi
     PREV["$name"]="$key"
     FINAL["$name"]="$running|$health|$status"
   done< <(container_rows)
   [[ ${#IDS[@]} -gt 0 ]]||{ fail CONTAINER "No Microsoft Tunnel containers were found";return 1;}
   now=$(date +%s);elapsed=$((now-start_epoch))
   [[ $waiting -eq 0 ]]&&break
   [[ $elapsed -ge $HEALTH_WAIT_SECONDS ]]&&break
   progress RUNNING CONTAINER-WAIT "${wait_targets% }" "Waiting for startup health: ${elapsed}s of ${HEALTH_WAIT_SECONDS}s elapsed; polling at intervals of up to 5s"
   if ((HEALTH_WAIT_SECONDS-elapsed < 5));then sleep "$((HEALTH_WAIT_SECONDS-elapsed))";else sleep 5;fi
 done
 now=$(date +%s);elapsed=$((now-start_epoch))
 local found_agent=0 found_server=0
 for name in "${!IDS[@]}";do
   [[ "$name" =~ mstunnel-agent ]]&&found_agent=1
   [[ "$name" =~ mstunnel-server|ocserv ]]&&found_server=1
   IFS='|' read -r running health status <<<"${FINAL[$name]}"
   role=Container;[[ "$name" =~ mstunnel-agent ]]&&role=Agent;[[ "$name" =~ mstunnel-server|ocserv ]]&&role=Server
   if [[ "$running" == yes && "$health" == healthy ]];then pass "CONTAINER-$role-FINAL" "Name=$name | Running=yes | Health=healthy | Image=${IMAGES_MAP[$name]}"
   elif [[ "$running" == yes && "$health" == not-reported ]];then review "CONTAINER-$role-FINAL" "Name=$name is running but health is not reported after ${elapsed}s"
   else fail "CONTAINER-$role-FINAL" "Name=$name | Running=$running | Health=$health | State=$status | Observed for ${elapsed}s";final_bad=1;fi
   if [[ "$running" != yes || "$health" != healthy ]];then
     container_log_snapshot "${IDS[$name]}" "$name" "Final health evidence"
   else
     container_log_snapshot "${IDS[$name]}" "$name" "Final health evidence" 0
   fi
   if have mst-cli;then
     if [[ "$role" == Agent || "$role" == Server ]];then
       local component="${role,,}"
       step "STATUS-$component" "$name" "Run mst-cli $component status and save its output"
       if mst-cli "$component" status >"$OUT/mst-cli-$component-status.txt" 2>&1;then
         progress INFO "STATUS-$component" "$name" "Status command completed; output saved"
       else
         progress REVIEW "STATUS-$component" "$name" "Status command failed; inspect mst-cli-$component-status.txt"
       fi
     fi
   fi
 done
 [[ $found_agent -eq 1 ]]||{ fail CONTAINER-Agent "Agent container not found";final_bad=1;}
 [[ $found_server -eq 1 ]]||{ fail CONTAINER-Server "Server container not found";final_bad=1;}
 return "$final_bad"
}

proxy_checks(){
 phase "Proxy configuration"
 step PROXY-HOST "host and mstunnel_monitor" "Read proxy environment variables, /etc/mstunnel/env.sh and systemctl show Environment; save redacted values"
 { env|grep -Ei '^(http|https|no)_proxy='||true
   [[ -r /etc/mstunnel/env.sh ]]&&grep -Ei '(http|https|no)_proxy=' /etc/mstunnel/env.sh||true
   systemctl show mstunnel_monitor -p Environment 2>/dev/null||true
 }|redact>"$OUT/proxy-host.txt"
 grep -Eiq '(http|https)_proxy=' "$OUT/proxy-host.txt"&&pass PROXY-HOST "Host proxy configured; see proxy-host.txt"||info PROXY-HOST "No host HTTP/HTTPS proxy detected"
 [[ "$ENGINE" != none ]]||{ skip PROXY-ENGINE "No container engine is available; engine and container proxy inspection skipped";return;}
 step PROXY-ENGINE "$ENGINE" "Query container-engine info for HTTP, HTTPS and bypass proxy settings; do not modify them"
 if [[ "$ENGINE" == docker ]];then
   docker info 2>/dev/null|grep -Ei 'HTTP Proxy|HTTPS Proxy|No Proxy'|redact>"$OUT/proxy-engine.txt"||true
 else
   podman info --format json 2>/dev/null|grep -Ei 'http_proxy|https_proxy|no_proxy'|redact>"$OUT/proxy-engine.txt"||true
 fi
 [[ -s "$OUT/proxy-engine.txt" ]]&&pass PROXY-ENGINE "$ENGINE engine proxy detected"||info PROXY-ENGINE "No $ENGINE engine proxy detected"
 local id n status image
 while IFS='|' read -r id n status image;do
   step "PROXY-$n" "$n ($id)" "Inspect container proxy environment and save redacted values"
   "$ENGINE" inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null|grep -Ei '^(http|https|no)_proxy='|redact>"$OUT/proxy-$n.txt"||true
   grep -Eiq '^(http|https)_proxy=' "$OUT/proxy-$n.txt"&&pass "PROXY-$n" configured||info "PROXY-$n" "No container HTTP/HTTPS proxy detected"
 done< <(container_rows)
}
inventory(){
 local ID VERSION_ID PRETTY_NAME VERSION
 phase "Host and supportability"
 step HOST /etc/os-release "Read Linux release, kernel (uname -r) and architecture (uname -m)"
 [[ -r /etc/os-release ]]&&. /etc/os-release||true
 info HOST "${PRETTY_NAME:-unknown}; kernel=$(uname -r); arch=$(uname -m)"
 step SUPPORT "$ENGINE" "Compare Linux release and container engine version with supported combinations"
 supportability
 step RAM host "Read current memory totals with free -h"
 info RAM "$(free -h|awk '/Mem:/{print "Total=" $2 "; Used=" $3 "; Free=" $4 "; Available=" $7}')"
 step DISK / "Read root filesystem capacity and free space with df -h"
 info DISK "$(df -h /|awk 'NR==2{print "Total=" $2 "; Used=" $3 "; Available=" $4 "; Usage=" $5}')"
 step TUN /dev/net/tun "Check whether the TUN device exists"
 [[ -e /dev/net/tun ]]&&pass TUN present||fail TUN missing
 step IPFORWARD net.ipv4.ip_forward "Read IPv4 forwarding with sysctl -n; do not change it"
 [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null||echo 0)" == 1 ]]&&pass IPFORWARD enabled||fail IPFORWARD disabled
 phase "Tunnel configuration"
 step ID "$AGENT" "Read SiteId, ServerId and ConfigId"
 info ID "SiteId=$(json_get "$AGENT" SiteId); ServerId=$(json_get "$AGENT" ServerId); ConfigId=$(json_get "$AGENT" ConfigId)"
 step NETWORK "$ADMIN; $OCS" "Read configured and effective client IPv4 networks without modifying them"
 info NETWORK "ClientNetwork=$(json_get "$ADMIN" Network); Effective=$(conf_values ipv4-network|head -1)"
 step PROXY host "Inspect host, service and container proxy settings; redact credential-bearing values"
 proxy_checks
 run_diagnostic containers_health || true
}
endpoints(){ phase "Required endpoint connectivity";local list="$OUT/endpoints.txt" src="$OUT/official-readiness.sh";curl -fsSL --max-time 60 "$READY_URL" -o "$src"||true;{ grep -Eo 'https?://[A-Za-z0-9._*-]+' "$src" 2>/dev/null|sed -E 's#https?://##';grep -Eo '([*]\.)?([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' "$src" 2>/dev/null;}|tr '[:upper:]' '[:lower:]'|sed -E 's#[/:].*$##'|grep -E '^([a-z0-9-]+\.)+[a-z]{2,24}$'|grep -Ev '^\*\.|\.(pem|crt|cer|key|json|conf|log|txt|sh|html)$'|sort -u>"$list";local total;total=$(wc -l<"$list");if [[ $MAX_ENDPOINTS -gt 0 ]];then head -n "$MAX_ENDPOINTS" "$list">"$list.tmp";mv "$list.tmp" "$list";review CONN-LIMIT "Testing first $MAX_ENDPOINTS of $total endpoints";fi;total=$(wc -l<"$list");[[ $total -gt 0 ]]||{ fail CONN-EMPTY "No endpoints discovered";return;};probe_scope(){ local type="$1" cid="$2" name="$3" host rc dns out http n=0 timing issuer tlsver;while read -r host;do ((++n));rc=0;dns=PASS;out="$OUT/.conn.$$";if [[ "$type" == host ]];then getent hosts "$host">/dev/null||dns=FAIL;curl -sSvI --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w '%{time_connect}|%{time_appconnect}|%{time_total}|%{ssl_verify_result}' "https://$host/" -o /dev/null 2>"$out" >"$out.time"||rc=$?;else "$ENGINE" exec "$cid" getent hosts "$host">/dev/null 2>&1||dns=FAIL;"$ENGINE" exec "$cid" sh -c 'curl -sSvI --connect-timeout "$1" --max-time "$1" -w "%{time_connect}|%{time_appconnect}|%{time_total}|%{ssl_verify_result}" "https://$2/" -o /dev/null' sh "$TIMEOUT" "$host" 2>"$out" >"$out.time"||rc=$?;fi;http="$(grep -E '^< HTTP/' "$out"|tail -1|awk '{print $3}'||true)";timing="$(cat "$out.time" 2>/dev/null||echo 'n/a|n/a|n/a|n/a')";issuer="$(grep -im1 'issuer:' "$out"|sed 's/^[* ]*//'||true)";tlsver="$(grep -Eim1 'SSL connection using|TLSv1\.[23]' "$out"|sed 's/^[* ]*//'||true)";IFS='|' read -r tcp_time tls_time total_time verify_result <<<"$timing";[[ $rc -eq 0 ]]&&pass "CONN-$name-$n" "$host; DNS=$dns; TCP=${tcp_time}s; TLS=${tls_time}s; Total=${total_time}s; Verify=${verify_result}; HTTP=${http:-response}; Protocol=${tlsver:-unknown}; ${issuer:-Issuer=unknown}"||fail "CONN-$name-$n" "$host; DNS=$dns; TCP=${tcp_time}s; TLS=${tls_time}s; Total=${total_time}s; exit=$rc";rm -f "$out" "$out.time";done<"$list";pass "CONN-$name-SUMMARY" "Completed $n/$total endpoints";};probe_scope host '' Host;local id n status image;while IFS='|' read -r id n status image;do "$ENGINE" exec "$id" sh -c 'command -v curl >/dev/null' 2>/dev/null&&probe_scope container "$id" "$n"||skip "CONN-$n" "curl unavailable";done< <(container_rows); }
internal_test(){ phase "Internal application connectivity";if [[ ! "$INTERNAL_URL" =~ ^https?:// ]];then if [[ $NON_INTERACTIVE -eq 1||! -t 0 ]];then skip INTERNAL "No internal URL supplied";return;fi;read -rp 'Internal access-check URL (Enter to skip): ' INTERNAL_URL;[[ -n "$INTERNAL_URL" ]]||{ skip INTERNAL "Skipped by administrator";return;};fi;local id n status image rc out;while IFS='|' read -r id n status image;do rc=0;out="$OUT/internal-$n.log";"$ENGINE" exec "$id" sh -c 'curl -sSvI --connect-timeout "$1" --max-time "$1" "$2" -o /dev/null' sh "$TIMEOUT" "$INTERNAL_URL">/dev/null 2>"$out"||rc=$?;[[ $rc -eq 0 ]]&&pass "INTERNAL-$n" "$INTERNAL_URL reachable"||fail "INTERNAL-$n" "$INTERNAL_URL failed; exit=$rc";done< <(container_rows); }
certificate(){ phase "Tunnel public TLS certificate";local cert="$OUT/active.crt" path;path="$(awk -F= 'BEGIN{IGNORECASE=1}$1~/^[[:space:]]*server-cert[[:space:]]*$/{v=$0;sub(/^[^=]*=[[:space:]]*/,"",v);gsub(/"/,"",v);print v;exit}' "$OCS" 2>/dev/null||true)";for f in "$path" "/etc/mstunnel/certs/$path" /etc/mstunnel/certs/ocserv-active.crt;do [[ -r "$f" ]]&&openssl x509 -in "$f" -noout>/dev/null 2>&1&&{ cp "$f" "$cert";break;};done;[[ -s "$cert" ]]||timeout "$TIMEOUT" openssl s_client -connect 127.0.0.1:443 -showcerts </dev/null 2>/dev/null|awk '/BEGIN CERTIFICATE/{x=1}x{print}/END CERTIFICATE/{exit}'>"$cert"||true;openssl x509 -in "$cert" -noout>/dev/null 2>&1||{ review CERT "Active certificate not located";return;};openssl x509 -in "$cert" -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName -ext keyUsage -ext extendedKeyUsage -ext authorityInfoAccess -ext crlDistributionPoints>"$OUT/certificate.txt" 2>&1||true;pass CERT "Certificate parsed successfully";while IFS= read -r certline;do info CERT-DETAIL "$certline";done<"$OUT/certificate.txt";local key bits sig policy st=REVIEW reason="Compatibility not determined";key="$(openssl x509 -in "$cert" -noout -text|awk -F: '/Public Key Algorithm/{gsub(/^[ ]+/,"",$2);print $2;exit}')";bits="$(openssl x509 -in "$cert" -noout -text|sed -nE 's/^[[:space:]]*Public-Key: \(([0-9]+) bit\).*/\1/p'|head -1)";sig="$(openssl x509 -in "$cert" -noout -text|awk -F: '/Signature Algorithm/{gsub(/^[ ]+/,"",$2);print $2;exit}')";policy="$(conf_values tls-priorities|head -1)";if echo "$key"|grep -Eqi 'rsa';then if [[ -n "$bits"&&"$bits" -lt 2048 ]]||echo "$sig"|grep -Eqi 'sha1|md5';then st=FAIL;reason="Unsupported weak RSA/signature";elif echo "$policy"|grep -q 'ECDHE-RSA';then st=PASS;reason="RSA certificate compatible with ECDHE-RSA policy";fi;elif echo "$key"|grep -Eqi 'ecPublicKey';then echo "$policy"|grep -q 'ECDHE-ECDSA'&&{ st=PASS;reason="ECDSA compatible";}||{ st=FAIL;reason="ECDSA certificate but ECDHE-ECDSA absent";};fi;emit "$st" CERT-ALGORITHM "$reason; Key=$key/$bits; Signature=$sig";info CERT-POLICY "tls-priorities=${policy:-not found}";echo "$policy"|grep -q 'VERS-TLS1.2'&&pass TLS12 "TLS 1.2 enabled by effective policy"||review TLS12 "TLS 1.2 not confirmed in effective policy";echo "$policy"|grep -q 'VERS-TLS1.3'&&pass TLS13 "TLS 1.3 enabled by effective policy"||review TLS13 "TLS 1.3 not confirmed in effective policy";echo "$policy"|grep -q 'AES-256-GCM'&&pass CIPHER "AES-256-GCM enabled by effective policy"||review CIPHER "AES-256-GCM not confirmed in effective policy";grep -Eo '(https?|ldap|ldaps)://[^[:space:]]+' "$OUT/certificate.txt"|sed -E 's/[),]$//'|sort -u>"$OUT/revocation-urls.txt"||true;while read -r u;do [[ -n "$u" ]]&&info REVOCATION "$u";done<"$OUT/revocation-urls.txt"; }
release_map(){
 phase "Installed image version"
 local a s html json
 a="$(digest_get "$IMAGES" agentImageDigest)";s="$(digest_get "$IMAGES" serverImageDigest)"
 info DIGEST "Agent=$a; Server=$s"
 html="$OUT/update-history.html";json="$OUT/release.json"
 curl -fsSL --max-time 60 "$UPGRADE_URL" -o "$html"||{ review RELEASE "Update history unavailable";return 1;}
 if ! python3 - "$html" "$json" "$a" "$s" <<'PY'
import re,html,json,sys
x=html.unescape(re.sub('<[^>]+>',' ',open(sys.argv[1],errors='replace').read()));x=re.sub(r'\s+',' ',x);p=re.compile(r'((?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, 20\d{2}).{0,500}?Version Number:\s*([0-9]{8}(?:\.[0-9]+)?(?:-[0-9]+)?).{0,700}?agentImageDigest\s*:?\s*(sha256:[0-9a-f]{64}).{0,500}?serverImageDigest\s*:?\s*(sha256:[0-9a-f]{64})',re.I);r=[{'date':d,'version':v,'agent':a.lower(),'server':s.lower()} for d,v,a,s in p.findall(x)];m=next((z for z in r if z['agent']==sys.argv[3] and z['server']==sys.argv[4]),None);json.dump({'latest':r[0] if r else None,'installed':m},open(sys.argv[2],'w'),indent=2)
PY
 then
 fail RELEASE "Unable to parse update history";return 1
 fi
 info RELEASE "Mapping saved to release.json"
 rm -f "$html"
}

revocation_checks(){
 phase "Certificate revocation connectivity"
 local urls="$OUT/revocation-urls.txt" total=0 passed=0 failed=0 reviewed=0 url scheme host port rc http tmp id name status image
 [[ -s "$urls" ]]||{ review CRL-SUMMARY "No CRL/OCSP/AIA URL discovered";return;}
 while IFS= read -r url;do [[ -n "$url" ]]||continue;((++total));scheme="${url%%:*}";host="$(printf %s "$url"|sed -En 's#^[a-zA-Z]+://([^/:]+).*#\1#p')"
  [[ -n "$host" ]]||{ review "REVOCATION-$total" "Hostless $scheme URL cannot be probed: $url";((++reviewed));continue;};rc=0;http=none;tmp="$OUT/revocation-$total.bin"
  if [[ "$scheme" =~ ^https?$ ]];then curl -sSL --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w '%{http_code}' "$url" -o "$tmp" >"$tmp.http" 2>"$tmp.err"||rc=$?;http="$(cat "$tmp.http" 2>/dev/null||echo none)";else port=389;[[ "$scheme" == ldaps ]]&&port=636;timeout "$TIMEOUT" bash -c "cat </dev/null >/dev/tcp/$host/$port" 2>"$tmp.err"||rc=$?;fi
  if [[ $rc -eq 0 ]];then pass "REVOCATION-$total" "URL reachable from Linux host; HTTP=$http; URL=$url";((++passed));else fail "REVOCATION-$total" "URL failed from Linux host; exit=$rc; URL=$url";((++failed));fi
  while IFS='|' read -r id name status image;do [[ "$name" =~ mstunnel-agent|mstunnel-server|ocserv ]]||continue;rc=0;if [[ "$scheme" =~ ^https?$ ]];then "$ENGINE" exec "$id" sh -c 'curl -sSIL --connect-timeout "$1" --max-time "$1" "$2" -o /dev/null' sh "$TIMEOUT" "$url" >/dev/null 2>&1||rc=$?;else "$ENGINE" exec "$id" sh -c 'timeout "$1" sh -c "cat </dev/null >/dev/tcp/$2/$3"' sh "$TIMEOUT" "$host" "$port" >/dev/null 2>&1||rc=$?;fi;[[ $rc -eq 0 ]]&&pass "REVOCATION-$name-$total" "URL reachable: $url"||fail "REVOCATION-$name-$total" "URL failed; exit=$rc: $url";done< <(container_rows)
 done<"$urls"
 [[ $failed -eq 0&&$passed -gt 0 ]]&&pass CRL-SUMMARY "Revocation connectivity passed; URLs=$total; HostPass=$passed; Review=$reviewed"||{ [[ $failed -gt 0 ]]&&fail CRL-SUMMARY "Revocation failures=$failed; HostPass=$passed; Review=$reviewed"||review CRL-SUMMARY "Revocation not conclusively validated";}
}

release_health(){
 run_diagnostic release_map || return 1
 local -a x=()
 mapfile -t x < <(python3 - "$OUT/release.json" <<'PYR'
import json,sys
x=json.load(open(sys.argv[1]));l=x.get('latest') or {};i=x.get('installed') or {}
print(l.get('version',''));print(l.get('date',''));print(i.get('version',''));print(i.get('date',''));print('true' if l and i and l==i else 'false')
PYR
 )
 if [[ "${x[4]}" == true ]];then pass RELEASE-HEALTH "Healthy: installed digest pair matches latest release ${x[0]}, released ${x[1]}";elif [[ -n "${x[2]}" ]];then review RELEASE-HEALTH "Installed release=${x[2]} (${x[3]}); latest=${x[0]} (${x[1]})";else fail RELEASE-HEALTH "Installed digest pair is not found in published history; latest=${x[0]} (${x[1]})";fi
}

full_diagnostics(){
 inventory;endpoints;internal_test;certificate;revocation_checks
 run_diagnostic release_health || true
}

preview_all(){
 phase "Preview everything"
 info PREVIEW-ALL "Running full diagnostics and every troubleshooting workflow in preview mode"
 local old="$SCENARIO";EXECUTE=0
 full_diagnostics
 for SCENARIO in unhealthy ip-starvation bridge-conflict container-down upgrade network-trace;do
   troubleshoot || review "PREVIEW-$SCENARIO" "Scenario preview could not complete; see findings above"
 done
 SCENARIO="$old";info PREVIEW-ALL "Diagnostics and scenario previews finished; baseline checks were reused; no remediation executed"
}

latest_release_values(){
 local json="$OUT/release.json"
 run_diagnostic release_map || return 1
 mapfile -t LATEST_RELEASE < <(python3 - "$json" <<'PYR'
import json,sys
x=json.load(open(sys.argv[1]));l=x.get('latest') or {}
print(l.get('date',''));print(l.get('version',''));print(l.get('agent',''));print(l.get('server',''))
PYR
 )
 [[ "${LATEST_RELEASE[2]:-}" =~ ^sha256:[0-9a-f]{64}$ && "${LATEST_RELEASE[3]:-}" =~ ^sha256:[0-9a-f]{64}$ ]]
}

start_upgrade_live_monitor(){
 local since="$1"
 : >"$OUT/upgrade-live.log";: >"$OUT/upgrade-events.log"
 journalctl -f --since "$since" -t mstunnel_monitor -t mstunnel-agent -t ocserv --no-pager >>"$OUT/upgrade-live.log" 2>&1 & UPGRADE_LOG_PID=$!
 pass UPGRADE-MONITOR "Live journal capture started; PID=$UPGRADE_LOG_PID"
}
stop_upgrade_live_monitor(){ [[ -n "${UPGRADE_LOG_PID:-}" ]]&&kill "$UPGRADE_LOG_PID" 2>/dev/null||true;wait "${UPGRADE_LOG_PID:-}" 2>/dev/null||true;UPGRADE_LOG_PID="";}
record_container_snapshot(){ local label="${1:-snapshot}" id name status image file;file="$OUT/containers-$label.txt";:>"$file";while IFS='|' read -r id name status image;do [[ -n "$id" ]]||continue;printf 'Name=%s\nId=%s\nStatus=%s\nImage=%s\nStartedAt=%s\nImageId=%s\n---\n' "$name" "$id" "$status" "$image" "$($ENGINE inspect --format '{{.State.StartedAt}}' "$id" 2>/dev/null||true)" "$($ENGINE inspect --format '{{.Image}}' "$id" 2>/dev/null||true)" >>"$file";done< <(container_rows);info UPGRADE-SNAPSHOT "Saved $file";}
assess_upgrade_evidence(){ local f="$OUT/upgrade-live.log" line;grep -Ei 'upgrade|image|pull|download|digest|manifest|layer|restart|starting service|healthy|done|complete|success|fail|error|timeout|unauthorized|denied|not found' "$f" >"$OUT/upgrade-events.log" 2>/dev/null||true;grep -Eiq 'upgrade|images_configured|imageId=sha256' "$f"&&pass UPGRADE-ATTEMPT "Upgrade-processing evidence found"||review UPGRADE-ATTEMPT "No explicit upgrade-attempt line found";grep -Eiq 'pull|download|manifest|layer|fetch' "$f"&&pass UPGRADE-IMAGE-REQUEST "Image pull/download activity observed"||review UPGRADE-IMAGE-REQUEST "No explicit image-pull line observed; target images may already be cached";grep -Eiq 'restart|starting service mstunnel|stopping service mstunnel' "$f"&&pass UPGRADE-RESTART "Service/container restart activity observed"||review UPGRADE-RESTART "No restart event identified";grep -Eiq 'upgrade done|upgrade complete|successfully upgraded|imageId=sha256' "$f"&&pass UPGRADE-RESULT "Upgrade completion evidence found"||review UPGRADE-RESULT "No explicit completion line found";grep -Eiq 'upgrade.*fail|pull.*fail|manifest.*unknown|unauthorized|denied|not found|timeout|error.*upgrade' "$f"&&fail UPGRADE-ERRORS "Failure evidence detected; review upgrade-events.log"||pass UPGRADE-ERRORS "No upgrade failure signature found";while IFS= read -r line;do info UPGRADE-EVENT "$line";done< <(tail -n 40 "$OUT/upgrade-events.log");}

force_upgrade_latest(){
 phase "Force upgrade to latest published release"
 run_diagnostic release_health || return 1
 latest_release_values||{ fail UPGRADE "Latest published digest pair could not be validated";return 1;}
 local release_date="${LATEST_RELEASE[0]}" release_version="${LATEST_RELEASE[1]}" target_agent="${LATEST_RELEASE[2]}" target_server="${LATEST_RELEASE[3]}"
 local current_agent current_server msg backup approval i upgrade_start
 current_agent="$(digest_get "$IMAGES" agentImageDigest)";current_server="$(digest_get "$IMAGES" serverImageDigest)"
 info UPGRADE-TARGET "Version=$release_version | ReleaseDate=$release_date | Agent=$target_agent | Server=$target_server"
 action UPGRADE-PLAN "Save current version; back up images_configured; generate validated upgrade message with mst_use_custom_image=1; start packet capture; submit to messages/in; monitor mstunnel_monitor; stop capture; verify final digests and container health"
 review UPGRADE-IMPACT "Microsoft Tunnel availability can be interrupted while agent/server containers are replaced"
 msg="$OUT/images_configured.upgrade";[[ -r "$IMAGES" ]]||{ fail UPGRADE "$IMAGES is unavailable";return 1;};[[ -d "$INBOX"&&-w "$INBOX" ]]||{ fail UPGRADE "$INBOX is not writable";return 1;}
 cp "$IMAGES" "$msg"
 python3 - "$msg" "$target_agent" "$target_server" <<'PYU'
import re,sys
p,a,s=sys.argv[1:];t=open(p).read()
t,n1=re.subn(r'(agentImageDigest[^s]{0,120})sha256:[0-9a-fA-F]{64}',lambda m:m.group(1)+a,t,1,flags=re.I)
t,n2=re.subn(r'(serverImageDigest[^s]{0,120})sha256:[0-9a-fA-F]{64}',lambda m:m.group(1)+s,t,1,flags=re.I)
t,n3=re.subn(r'(mst_use_custom_image\s*[=:]\s*["\x27]?)[01]',lambda m:m.group(1)+'1',t,1,flags=re.I)
if (n1,n2)!=(1,1):raise SystemExit('digest replacement failed')
if n3==0:t+='\nmst_use_custom_image="1"\n'
open(p,'w').write(t)
PYU
 [[ "$(digest_get "$msg" agentImageDigest)" == "$target_agent"&&"$(digest_get "$msg" serverImageDigest)" == "$target_server" ]]&&pass UPGRADE-MESSAGE "Generated upgrade message validated"||{ fail UPGRADE-MESSAGE "Generated message validation failed";return 1;}
 if [[ $EXECUTE -ne 1 ]];then review UPGRADE "Preview complete. No upgrade message was submitted. Rerun with --execute to apply.";return 0;fi
 read -rp 'Type FORCE-UPGRADE-LATEST to continue: ' approval;[[ "$approval" == FORCE-UPGRADE-LATEST ]]||{ review UPGRADE "Canceled by administrator";return 1;}
 backup="$IMAGES.backup.$TS";cp -p "$IMAGES" "$backup";[[ -r "$VER" ]]&&cp "$VER" "$OUT/version-info-before.json";pass UPGRADE-BACKUP "Backup created: $backup"
 record_container_snapshot before-upgrade
 upgrade_start="$(date --iso-8601=seconds)";start_upgrade_live_monitor "$upgrade_start"
 start_capture "$OUT/upgrade.pcap"||review UPGRADE-TRACE "Upgrade continues without local packet capture"
 cp "$msg" "$INBOX/images_configured.upgrade";pass UPGRADE-SUBMIT "Upgrade message submitted at $upgrade_start"
 for ((i=0;i<MONITOR_SECONDS;i+=5));do printf '\r[INFO] Monitoring force upgrade: %s/%ss | message=%s' "$i" "$MONITOR_SECONDS" "$([[ -e "$INBOX/images_configured.upgrade" ]]&&echo pending||echo consumed)";sleep 5;done;printf '\n'
 stop_upgrade_live_monitor;journalctl -t mstunnel_monitor --since "$upgrade_start" --no-pager>"$OUT/upgrade-monitor.log" 2>&1||true;stop_capture
 record_container_snapshot after-upgrade
 assess_upgrade_evidence
 [[ ! -e "$INBOX/images_configured.upgrade" ]]&&pass UPGRADE-CONSUMED "Upgrade message was consumed"||review UPGRADE-CONSUMED "Upgrade message remains in incoming directory"
 [[ "$(digest_get "$IMAGES" agentImageDigest)" == "$target_agent" ]]&&pass UPGRADE-AGENT "Agent digest matches $release_version ($release_date)"||fail UPGRADE-AGENT "Agent digest does not match target"
 [[ "$(digest_get "$IMAGES" serverImageDigest)" == "$target_server" ]]&&pass UPGRADE-SERVER "Server digest matches $release_version ($release_date)"||fail UPGRADE-SERVER "Server digest does not match target"
 containers_health||true
}

security_inventory_payload(){
 cat <<'SH'
set -eu
if [ -r /etc/os-release ];then
 grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release
else
 printf 'REVIEW: /etc/os-release unavailable\n'
fi
if command -v dpkg-query >/dev/null 2>&1;then
 packages=$(dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n') || exit 1
 printf '%s\n' "$packages" | awk -F '\t' '
  $3 == "installed" && $1 ~ /^(libc6|libc-bin|locales|python3-jwt|python3[.]12|python3[.]12-minimal|libpython3[.]12-minimal|libpython3[.]12-stdlib|libpython3[.]12t64)(:.*)?$/ {
   printf "PACKAGE: %s = %s\n", $1, $2
   n++
  }
  END { if (!n) print "REVIEW: No matching installed Debian packages; this does not establish CVE absence" }
 '
else
 printf 'REVIEW: dpkg-query unavailable; Ubuntu package inventory cannot be collected in this scope\n'
fi
if command -v python3 >/dev/null 2>&1;then
 python3 -I - <<'PYSEC'
import importlib.metadata
import sys
print("PYTHON: " + sys.executable + " | " + sys.version.split()[0])
try:
    distribution = importlib.metadata.distribution("PyJWT")
except importlib.metadata.PackageNotFoundError:
    print("PYJWT: Not found in this interpreter's isolated search path")
else:
    print("PYJWT: " + distribution.version + " | Location=" + str(distribution.locate_file("jwt")))
PYSEC
else
 printf 'REVIEW: python3 unavailable; PyJWT runtime metadata cannot be collected\n'
fi
SH
}

security_inventory_scope(){
 local label="$1" engine="${2:-}" id="${3:-}" rc=0 line
 local file="$OUT/security-$label.txt"
 if [[ -z "$engine" ]];then
  security_inventory_payload | timeout "$TIMEOUT" sh -s >"$file" 2>"$file.error" || rc=$?
 else
  security_inventory_payload | timeout "$TIMEOUT" "$engine" exec -i "$id" sh -s >"$file" 2>"$file.error" || rc=$?
 fi
 if [[ $rc -ne 0 ]];then
  review "SECURITY-$label" "Inventory incomplete; exit=$rc; see $file and $file.error"
 fi
 while IFS= read -r line;do
  if [[ "$line" == REVIEW:* ]];then review "SECURITY-$label" "${line#REVIEW: }"
  else info "SECURITY-$label" "$line";fi
 done <"$file"
 return "$rc"
}

security_inventory(){
 phase "Read-only security package inventory"
 info SECURITY-SCOPE "Host and running Tunnel containers are separate package scopes. Findings are inventory only, not a declaration that CVEs are fixed"
 [[ $EXECUTE -ne 1 ]]||info SECURITY-READONLY "--execute is ignored in security-inventory mode"
 security_inventory_scope host || true
 local engine id name status image metadata running image_id found_engine=0 found_container=0
 for engine in docker podman;do
  have "$engine"||continue
  found_engine=1
  if ! timeout "$TIMEOUT" "$engine" ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' >"$OUT/security-$engine-containers.txt" 2>"$OUT/security-$engine-containers.error";then
   review "SECURITY-$engine" "Container enumeration failed; see security-$engine-containers.error"
   continue
  fi
  while IFS='|' read -r id name status image;do
   [[ -n "$id" && "$name $image" =~ mstunnel|ocserv ]]||continue
   found_container=1
   info "SECURITY-$engine-$id" "Container=$name | ID=$id | Image=$image | State=$status"
   if ! metadata="$(timeout "$TIMEOUT" "$engine" inspect --format '{{.State.Running}}|{{.Image}}' "$id" 2>"$OUT/security-$engine-$id-inspect.error")";then
    review "SECURITY-$engine-$id" "Container inspection failed; package scope could not be collected"
    continue
   fi
   IFS='|' read -r running image_id <<<"$metadata"
   info "SECURITY-$engine-$id" "ImageID=$image_id"
   if [[ "$running" != true ]];then
    review "SECURITY-$engine-$id" "Container is not running; it was not started or modified to collect packages"
    continue
   fi
   security_inventory_scope "$engine-$id" "$engine" "$id" || true
  done <"$OUT/security-$engine-containers.txt"
 done
 if [[ $found_engine -eq 0 ]];then
  review SECURITY-CONTAINERS "Neither Docker nor Podman is available; container inventory was not collected"
 elif [[ $found_container -eq 0 ]];then
  review SECURITY-CONTAINERS "No Tunnel containers were inventoried; this does not establish absence of vulnerable images"
 fi
 review SECURITY-COVERAGE "User-site packages, other virtual environments, stopped containers and unused images are not scanned. Portal asset attribution still requires correlation"
 info SECURITY-ADVISORIES "glibc: https://ubuntu.com/security/notices/USN-8737-2 | Python: https://ubuntu.com/security/notices/USN-8744-1"
 info SECURITY-PYJWT "Use the full Ubuntu python3-jwt package revision to assess backports; the PyJWT runtime version alone is insufficient. Do not overwrite system packages with pip"
}

security_update_holds(){
 local package held
 if ! apt-mark showhold >"$OUT/security-held-packages.txt" 2>"$OUT/security-held-packages.error";then
  fail SECURITY-UPDATES "Could not inspect held packages; see security-held-packages.error"
  return 1
 fi
 for package in "$@";do
  while IFS= read -r held;do
   if [[ "${package%%:*}" == "${held%%:*}" ]];then
    review SECURITY-UPDATES "Selected package is held: $held. Resolve the hold through your change process; it will not be overridden"
    return 1
   fi
  done <"$OUT/security-held-packages.txt"
 done
}

security_update_interactive(){ [[ $NON_INTERACTIVE -eq 0 && -t 0 ]]; }

security_updates(){
 phase "Ubuntu host package update plan"
 local c line package approval
 local -a packages=()
 if [[ $EXECUTE -eq 1 ]] && ! security_update_interactive;then
  fail SECURITY-UPDATES "--execute requires an interactive terminal; unattended package updates are disabled"
  return 2
 fi
 for c in apt-get apt-mark dpkg-query tee;do
  have "$c"||{ fail SECURITY-UPDATES "Required host command unavailable: $c";return 1;}
 done
 security_inventory_scope host-before-updates || return 1
 local before="$OUT/security-host-before-updates.txt"
 if ! grep -Eq '^ID=("ubuntu"|ubuntu)$' "$before" || ! grep -Eq '^VERSION_ID=("24[.]04"|24[.]04)$' "$before";then
  fail SECURITY-UPDATES "This update workflow supports only the Ubuntu 24.04 host; no package changes were made"
  return 1
 fi
 while IFS= read -r line;do
  [[ "$line" == "PACKAGE: "* ]]||continue
  package="${line#PACKAGE: }";package="${package%% = *}"
  if [[ ! "$package" =~ ^[a-z0-9][a-z0-9.+-]*(:[a-z0-9][a-z0-9-]*)?$ ]];then
   fail SECURITY-UPDATES "Invalid package name in host inventory; refusing to construct an update command"
   return 1
  fi
  packages+=("$package")
 done <"$before"
 [[ ${#packages[@]} -gt 0 ]]||{ fail SECURITY-UPDATES "No selected installed packages found; no changes made";return 1;}
 security_update_holds "${packages[@]}" || return 1
 info SECURITY-UPDATES "Selected installed packages: $(IFS=', ';echo "${packages[*]}")"
 review SECURITY-UPDATES "This is a targeted package update, not a security-only APT filter or a guarantee that all CVEs are fixed. Dependencies may also change"
 if [[ $EXECUTE -eq 1 ]];then
  review SECURITY-IMPACT "Use an approved maintenance window and a recoverable host backup. Package scripts may restart services and interrupt Tunnel. This workflow does not roll back packages or reboot"
  if ! read -rp 'Type REFRESH-HOST-SECURITY-PLAN to refresh APT metadata (no package installation yet): ' approval || [[ "$approval" != REFRESH-HOST-SECURITY-PLAN ]];then
   review SECURITY-UPDATES "Canceled before metadata refresh"
   return 0
  fi
  if ! apt-get -o APT::Update::Error-Mode=any update 2>&1 | tee "$OUT/security-apt-update.log";then
   fail SECURITY-UPDATES "APT metadata refresh failed; no package installation attempted"
   return 1
  fi
 else
  info SECURITY-UPDATES "Preview only: using cached APT metadata, which may be stale; no repositories or packages will be changed"
 fi
 if ! apt-get --simulate install --only-upgrade --no-remove "${packages[@]}" 2>&1 | tee "$OUT/security-apt-plan.log";then
  fail SECURITY-UPDATES "APT simulation failed; no package installation attempted"
  return 1
 fi
 [[ $EXECUTE -eq 1 ]]||{ info SECURITY-UPDATES "Plan saved to security-apt-plan.log. Use --execute interactively only after reviewing the maintenance impact";return 0;}
 if ! read -rp 'Review the plan above. Type APPLY-HOST-SECURITY-UPDATES to install it: ' approval || [[ "$approval" != APPLY-HOST-SECURITY-UPDATES ]];then
  review SECURITY-UPDATES "Canceled; metadata was refreshed but no packages were installed"
  return 0
 fi
 security_update_holds "${packages[@]}" || return 1
 if ! apt-get --yes install --only-upgrade --no-remove "${packages[@]}" 2>&1 | tee "$OUT/security-apt-install.log";then
  fail SECURITY-UPDATES "APT installation failed or was interrupted; packages may be partially updated. Review security-apt-install.log before retrying"
  security_inventory_scope host-after-updates || true
  return 1
 fi
 pass SECURITY-UPDATES "APT transaction completed; this does not establish CVE clearance"
 security_inventory_scope host-after-updates || return 1
 if [[ -e /var/run/reboot-required ]];then
  review SECURITY-REBOOT "Ubuntu requests a reboot. Schedule it through your maintenance process; this script will not reboot"
 else
  info SECURITY-REBOOT "No Ubuntu reboot-required marker found; review APT service-restart messages separately"
 fi
 containers_health || true
 review SECURITY-RESCAN "Compare complete package revisions with Ubuntu advisories and request a compliance rescan. PyJWT's May CVEs must not be marked fixed solely because APT completed"
}

log_collection(){
 EXECUTE=0
 inventory
 phase "Bounded Tunnel journal collection"
 have journalctl||{ fail LOG-COLLECTION "journalctl is unavailable";return 1;}
 step LOG-COLLECTION journalctl "Collect up to 1000 short-iso entries since $LOG_SINCE for mstunnel_monitor, mstunnel-agent and ocserv; timeout 60s"
 if ! timeout 60 journalctl --since "$LOG_SINCE" --no-pager -o short-iso -n 1000 \
  -t mstunnel_monitor -t mstunnel-agent -t ocserv >"$OUT/tunnel-journal.log" 2>"$OUT/tunnel-journal.error";then
  fail LOG-COLLECTION "Journal collection failed; see tunnel-journal.error"
  return 1
 fi
 info LOG-COLLECTION "Saved $(wc -l <"$OUT/tunnel-journal.log") journal lines and available container health logs. No remediation or endpoint probes were run"
}

main_menu(){ cat <<'EOF'
Select an operation:
  1) Full diagnostics
  2) Inventory and certificate assessment
  3) Required endpoint connectivity
  4) Internal application connectivity
  5) Guided troubleshooting
  6) Preview everything: full diagnostics and all troubleshooting previews
  7) Production self-test
  8) Read-only security package inventory (host and Tunnel containers)
  9) Preview Ubuntu host package updates
  10) Collect Tunnel logs without remediation
  0) Exit
EOF
read -rp 'Selection [0-10]: ' x;case "$x" in 1)MODE=full;;2)MODE=inventory;;3)MODE=connectivity;;4)MODE=internal;;5)MODE=troubleshoot;;6)MODE=preview-all;;7)MODE=self-test;;8)MODE=security-inventory;;9)MODE=security-updates;;10)MODE=log-collection;;0)exit 0;;*)exit 2;;esac; }
trouble_menu(){ cat <<'EOF'
Select a Microsoft Tunnel troubleshooting workflow:
  1) Server unhealthy status
  2) Client IP-address starvation
  3) Docker/Podman bridge-network conflict
  4) Agent or server container down
  5) Upgrade failure / stuck upgrade
  6) VPN client cannot connect / packet capture
  0) Exit
EOF
read -rp 'Selection [0-6]: ' x;case "$x" in 1)SCENARIO=unhealthy;;2)SCENARIO=ip-starvation;;3)SCENARIO=bridge-conflict;;4)SCENARIO=container-down;;5)SCENARIO=upgrade;;6)SCENARIO=network-trace;;0)exit 0;;*)exit 2;;esac; }
restart_agent(){ if have mst-cli;then mst-cli agent restart;else "$ENGINE" restart "$($ENGINE ps -aqf name=mstunnel-agent|head -1)";fi; }
restart_server(){ if have mst-cli;then mst-cli server restart;else "$ENGINE" restart "$($ENGINE ps -aqf name=mstunnel-server|head -1)";fi; }
troubleshoot(){ [[ -n "$SCENARIO" ]]||trouble_menu;phase "Troubleshooting: $SCENARIO";case "$SCENARIO" in
 unhealthy)state="$(json_get "$AGENT" CurrentServerHealthStatus)";[[ "$state" == 1 ]]&&pass HEALTH "CurrentServerHealthStatus=1; already healthy"||action HEALTH "CurrentServerHealthStatus=$state; back up AgentSettings, set health to 1, restart agent, verify";[[ $EXECUTE -eq 1&&"$state" != 1 ]]||return 0;read -rp 'Type RESET-TUNNEL-HEALTH: ' a;[[ "$a" == RESET-TUNNEL-HEALTH ]]||return;cp -p "$AGENT" "$AGENT.backup.$TS";python3 - "$AGENT" <<'PY'
import json,sys,tempfile,os
p=sys.argv[1];d=json.load(open(p));d['CurrentServerHealthStatus']=1;fd,t=tempfile.mkstemp(dir=os.path.dirname(p));os.close(fd);json.dump(d,open(t,'w'),indent=2);os.replace(t,p)
PY
restart_agent;sleep 5;containers_health||true;;
 ip-starvation)net="$(json_get "$ADMIN" Network)";python3 - "$net" <<'PY'|tee "$OUT/subnet-capacity.txt"
import ipaddress,sys
try:n=ipaddress.ip_network(sys.argv[1],strict=False);print(f'[INFO] Network={n}; usable={max(n.num_addresses-2,0)}')
except:print('[REVIEW] Network unavailable')
PY
journalctl --since "$LOG_SINCE" -t ocserv --no-pager|grep -Ei 'could not figure out a valid IPv4 IP|ip-lease'>"$OUT/ip-errors.txt"||true;[[ -s "$OUT/ip-errors.txt" ]]&&action IP "Increase client IP range in Intune Server configuration"||pass IP "No allocation errors found";;
 bridge-conflict)ip -o route>"$OUT/routes.txt";if [[ "$ENGINE" == docker ]];then docker network inspect bridge>"$OUT/bridge.json" 2>&1||true;else podman network inspect podman>"$OUT/bridge.json" 2>&1||true;fi;python3 - "$OUT/routes.txt" "$OUT/bridge.json" <<'PY'>"$OUT/overlap.txt"
import ipaddress,re,sys
r=[]
for x in open(sys.argv[1]):
 m=re.match(r'(\d+\.\d+\.\d+\.\d+/\d+)',x)
 if m:
  try:r.append(ipaddress.ip_network(m.group(1),strict=False))
  except:pass
try:t=open(sys.argv[2]).read()
except:t=''
n=[]
for x in re.findall(r'\d+\.\d+\.\d+\.\d+/\d+',t):
 try:n.append(ipaddress.ip_network(x,strict=False))
 except:pass
for a in r:
 for b in n:
  if a.overlaps(b):print(a,b)
PY
[[ -s "$OUT/overlap.txt" ]]&&action BRIDGE "Readdress overlapping bridge through approved rebuild: $(head -1 "$OUT/overlap.txt")"||pass BRIDGE "No overlap detected";;
 container-down)run_diagnostic containers_health||true;[[ $EXECUTE -eq 1 ]]||{ review CONTAINER "Preview only; add --execute";return;};read -rp 'Type RESTART-TUNNEL: ' a;[[ "$a" == RESTART-TUNNEL ]]||return;restart_agent||true;restart_server||true;sleep 8;containers_health||true;;
 upgrade)force_upgrade_latest;;
 network-trace)action TRACE "Start capture, reproduce issue, press Enter, stop and package";[[ $EXECUTE -eq 1 ]]||{ review TRACE "Preview only; add --execute";return;};read -rp 'Type NETWORK-TRACE: ' a;[[ "$a" == NETWORK-TRACE ]]||return;start_capture "$OUT/network-trace.pcap"||return;echo 'Capture RUNNING. Reproduce issue now.';read -rp 'Press Enter when reproduction is complete: ' _;stop_capture;pass TRACE "Capture stopped";;
 *)fail TROUBLESHOOT "Unknown scenario";;esac; }
[[ -n "$MODE"||-n "$SCENARIO" ]]||main_menu;[[ -n "$SCENARIO"&&-z "$MODE" ]]&&MODE=troubleshoot
banner
preflight||{ package;exit 2;}
RUN_EXIT=0
case "$MODE" in
 log-collection)log_collection || RUN_EXIT=$?;;
 security-updates)security_updates || RUN_EXIT=$?;;
 security-inventory)security_inventory;;
 full)full_diagnostics;;
 inventory)inventory;certificate;revocation_checks;run_diagnostic release_health||true;; connectivity)inventory;endpoints;; internal)inventory;internal_test;; troubleshoot)troubleshoot;; preview-all)preview_all;; self-test)pass SELFTEST "Runtime prerequisites verified";; *)fail MODE "Invalid mode: $MODE";;esac
package
exit "$RUN_EXIT"
