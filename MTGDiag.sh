#!/usr/bin/env bash
# Microsoft Tunnel Guided Troubleshooter v6.2.0
# Owners: Anushka Rai and Yeswanth Kumar
set -Eeuo pipefail
IFS=$'\n\t'; umask 077
VERSION="6.2.0"
UPGRADE_URL="https://learn.microsoft.com/en-us/intune/device-security/microsoft-tunnel/upgrade#microsoft-tunnel-update-history"
SCENARIO=""; EXECUTE=0; LOG_SINCE="-4 hours"; OUT=""; CAPTURE_INTERFACE="any"; CAPTURE_FILTER="port 443"; MONITOR_SECONDS=300
AGENT_SETTINGS=/etc/mstunnel/AgentSettings.json
ADMIN_SETTINGS=/etc/mstunnel/admin-settings.json
IMAGES=/etc/mstunnel/images_configured
VERSION_INFO=/etc/mstunnel/version-info.json
MESSAGE_IN=/etc/mstunnel/messages/in
TCPDUMP_PID=""

usage(){ cat <<'EOF'
Usage: sudo ./MTGTroubleshooter-v6.1.sh [options]
  --scenario unhealthy|ip-starvation|bridge-conflict|container-down|upgrade|network-trace
  --execute                 Permit guarded remediation after typed approval
  --log-since TEXT          Default: -4 hours
  --output-dir PATH
  --capture-interface NAME  Default: any
  --capture-filter FILTER   Default: port 443
  --monitor-seconds N       Upgrade monitoring ceiling, default: 300
  --help | --version
Without --scenario, the script prompts for a troubleshooting workflow.
EOF
}
while (($#)); do case "$1" in
 --scenario) SCENARIO="${2:-}";shift 2;; --execute) EXECUTE=1;shift;;
 --log-since) LOG_SINCE="${2:-}";shift 2;; --output-dir) OUT="${2:-}";shift 2;;
 --capture-interface) CAPTURE_INTERFACE="${2:-}";shift 2;; --capture-filter) CAPTURE_FILTER="${2:-}";shift 2;;
 --monitor-seconds) MONITOR_SECONDS="${2:-}";shift 2;; --help|-h) usage;exit 0;; --version) echo "$VERSION";exit 0;;
 *) echo "Unknown option: $1" >&2;usage;exit 2;; esac;done
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root." >&2;exit 2; }
[[ "$MONITOR_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo "--monitor-seconds must be a positive integer" >&2;exit 2; }
TS="$(date -u +%Y%m%dT%H%M%SZ)";OUT="${OUT:-/tmp/mtg-troubleshoot-$TS}"
[[ ! -e "$OUT" || -z "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] || { echo "Output directory is not empty: $OUT" >&2;exit 3; }
mkdir -p "$OUT";chmod 700 "$OUT";REPORT="$OUT/report.txt";exec > >(tee -a "$REPORT") 2>&1

pass(){ echo "[PASS] $*";};fail(){ echo "[FAIL] $*";};info(){ echo "[INFO] $*";};review(){ echo "[REVIEW] $*";};action(){ echo "[ACTION] $*";}
have(){ command -v "$1" >/dev/null 2>&1; }
ENGINE=none;have podman&&ENGINE=podman;[[ "$ENGINE" == none ]]&&have docker&&ENGINE=docker
json_get(){ local f="$1" k="$2";[[ -r "$f" ]]||return 0;if have jq;then jq -r --arg k "$k" '.[$k]//empty' "$f" 2>/dev/null;else sed -nE 's/.*"'"$k"'"[[:space:]]*:[[:space:]]*"?([^",}]*)"?.*/\1/p' "$f"|head -1;fi; }
digest_get(){ grep -Eio "$2[^s]{0,120}sha256:[0-9a-f]{64}" "$1" 2>/dev/null|grep -Eo 'sha256:[0-9a-f]{64}'|head -1||true; }
container_rows(){ [[ "$ENGINE" != none ]]&&"$ENGINE" ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null|grep -Ei 'mstunnel|ocserv'||true; }
stop_capture(){ if [[ -n "${TCPDUMP_PID:-}" ]]&&kill -0 "$TCPDUMP_PID" 2>/dev/null;then kill -INT "$TCPDUMP_PID" 2>/dev/null||true;wait "$TCPDUMP_PID" 2>/dev/null||true;fi;TCPDUMP_PID=""; }
trap 'stop_capture' EXIT INT TERM
start_capture(){ local file="$1";have tcpdump||{ fail "tcpdump is required for packet capture";return 1;};info "Starting packet capture: interface=$CAPTURE_INTERFACE filter=$CAPTURE_FILTER file=$file";tcpdump -i "$CAPTURE_INTERFACE" -U -w "$file" $CAPTURE_FILTER >"$OUT/tcpdump.log" 2>&1 & TCPDUMP_PID=$!;sleep 2;kill -0 "$TCPDUMP_PID" 2>/dev/null||{ fail "tcpdump failed to start; see $OUT/tcpdump.log";TCPDUMP_PID="";return 1;};pass "Packet capture started (PID=$TCPDUMP_PID)"; }
agent_restart(){ if have mst-cli;then mst-cli agent restart;elif [[ "$ENGINE" != none ]];then local id;id="$($ENGINE ps -aqf name=mstunnel-agent|head -1)";[[ -n "$id" ]]&&$ENGINE restart "$id";else return 1;fi; }
server_restart(){ if have mst-cli;then mst-cli server restart;elif [[ "$ENGINE" != none ]];then local id;id="$($ENGINE ps -aqf name=mstunnel-server|head -1)";[[ -n "$id" ]]&&$ENGINE restart "$id";else return 1;fi; }
verify_containers(){ local bad=0 found_agent=0 found_server=0 id name status image health;while IFS='|' read -r id name status image;do [[ -n "$id" ]]||continue;health="$($ENGINE inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-reported{{end}}' "$id" 2>/dev/null||echo unknown)";[[ "$name" =~ mstunnel-agent ]]&&found_agent=1;[[ "$name" =~ mstunnel-server|ocserv ]]&&found_server=1;if [[ "$status" =~ Up|running ]]&&[[ "$health" == healthy || "$health" == not-reported ]];then pass "$name running; health=$health; image=$image";else fail "$name state=$status; health=$health; image=$image";bad=1;fi;done< <(container_rows);[[ $found_agent -eq 1 ]]||{ fail "mstunnel-agent not found";bad=1;};[[ $found_server -eq 1 ]]||{ fail "mstunnel-server not found";bad=1;};return "$bad"; }
package(){ stop_capture;tar -C "$OUT" -czf "$OUT/evidence.tar.gz" --exclude evidence.tar.gz . 2>/dev/null||true;printf '\nReport: %s\nEvidence: %s\n' "$REPORT" "$OUT/evidence.tar.gz"; }

menu(){ cat <<'EOF'
Select a Microsoft Tunnel troubleshooting and remediation workflow:
  1) Server unhealthy status                 [Automated reset available]
  2) Client IP-address starvation            [Guided Intune configuration action]
  3) Docker/Podman bridge-network conflict   [Guided rebuild action]
  4) Agent or server container down          [Automated restart available]
  5) Upgrade failure / stuck upgrade          [Force latest release available]
  6) VPN client cannot connect               [Start capture, reproduce, stop capture]
  0) Exit
EOF
 read -rp 'Selection [0-6]: ' x
 case "$x" in 1)SCENARIO=unhealthy;;2)SCENARIO=ip-starvation;;3)SCENARIO=bridge-conflict;;4)SCENARIO=container-down;;5)SCENARIO=upgrade;;6)SCENARIO=network-trace;;0)exit 0;;*)echo "Invalid selection";exit 2;;esac
}
[[ -n "$SCENARIO" ]]||menu
printf '%s\n' "================================================================================" " MICROSOFT TUNNEL GUIDED TROUBLESHOOTER" " Version: $VERSION | Scenario: $SCENARIO | Mode: $([[ $EXECUTE -eq 1 ]]&&echo EXECUTE||echo PREVIEW)" " Output: $OUT" "================================================================================"

case "$SCENARIO" in
unhealthy)
 state="$(json_get "$AGENT_SETTINGS" CurrentServerHealthStatus)";reason="$(json_get "$AGENT_SETTINGS" ReasonServerIsUnhealthy)";info "CurrentServerHealthStatus(raw)=${state:-unknown}; Reason(raw)=${reason:-unknown}"
 journalctl --since "$LOG_SINCE" -t mstunnel_monitor -t mstunnel-agent -t ocserv --no-pager>"$OUT/unhealthy-logs.txt" 2>&1||true
 if [[ "$state" == 1 ]];then pass "Server health state is already healthy; no change required.";else action "Back up AgentSettings.json, set CurrentServerHealthStatus to 1, restart agent, verify state and containers.";fi
 [[ $EXECUTE -eq 1 && "$state" != 1 ]]||{ [[ "$state" != 1 ]]&&review "Preview only. Rerun with --execute to apply.";package;exit 0;}
 read -rp 'Type RESET-TUNNEL-HEALTH to continue: ' a;[[ "$a" == RESET-TUNNEL-HEALTH ]]||exit 1
 cp -p "$AGENT_SETTINGS" "$AGENT_SETTINGS.backup.$TS"
 python3 - "$AGENT_SETTINGS" <<'PY'
import json,sys,tempfile,os
p=sys.argv[1];d=json.load(open(p));d['CurrentServerHealthStatus']=1
fd,t=tempfile.mkstemp(dir=os.path.dirname(p));os.close(fd)
with open(t,'w') as f:json.dump(d,f,indent=2)
os.chmod(t,0o600);os.replace(t,p)
PY
 agent_restart&&pass "Agent restart requested"||fail "Agent restart failed";sleep 5
 [[ "$(json_get "$AGENT_SETTINGS" CurrentServerHealthStatus)" == 1 ]]&&pass "Health state is now 1"||fail "Health state is not 1 after remediation";verify_containers||true;;
ip-starvation)
 net="$(json_get "$ADMIN_SETTINGS" Network)";python3 - "$net" <<'PY'|tee "$OUT/subnet-capacity.txt"
import ipaddress,sys
try:n=ipaddress.ip_network(sys.argv[1],strict=False);print(f'[INFO] Client network={n}; total addresses={n.num_addresses}; approximate usable={max(n.num_addresses-2,0)}')
except Exception:print('[REVIEW] Client network unavailable')
PY
 journalctl --since "$LOG_SINCE" -t ocserv --no-pager|grep -Ei 'could not figure out a valid IPv4 IP|ip-lease'>"$OUT/ip-allocation-errors.txt"||true;n="$(wc -l<"$OUT/ip-allocation-errors.txt")"
 if [[ "$n" -gt 0 ]];then fail "Found $n IP-allocation error lines.";action "Increase the client IP address range in the assigned Microsoft Tunnel Server configuration in Intune, then wait for configuration delivery and rerun this test.";else pass "No IP-allocation error signature found in selected log window.";fi
 review "This resolution is tenant-side and cannot be safely applied from the Linux server.";;
bridge-conflict)
 ip -o route>"$OUT/host-routes.txt";if [[ "$ENGINE" == docker ]];then docker network inspect bridge>"$OUT/engine-network.json" 2>&1||true;elif [[ "$ENGINE" == podman ]];then podman network inspect podman>"$OUT/engine-network.json" 2>&1||true;fi
 python3 - "$OUT/host-routes.txt" "$OUT/engine-network.json" <<'PY'>"$OUT/overlap.txt"
import ipaddress,re,sys
routes=[]
for x in open(sys.argv[1]):
 m=re.match(r'(\d+\.\d+\.\d+\.\d+/\d+)',x)
 if m:
  try:routes.append(ipaddress.ip_network(m.group(1),strict=False))
  except:pass
try:text=open(sys.argv[2]).read()
except:text=''
nets=[]
for x in re.findall(r'\d+\.\d+\.\d+\.\d+/\d+',text):
 try:nets.append(ipaddress.ip_network(x,strict=False))
 except:pass
for a in routes:
 for b in nets:
  if a.overlaps(b):print(f'{a}|{b}')
PY
 if [[ -s "$OUT/overlap.txt" ]];then fail "Bridge conflict detected: $(head -1 "$OUT/overlap.txt")";action "Select a non-overlapping Docker/Podman bridge subnet, then uninstall and reinstall/recreate Microsoft Tunnel containers using the approved change procedure.";review "Automatic bridge readdressing is blocked because it can break container networking and requires change control.";else pass "No host-route/container-bridge overlap detected.";fi;;
container-down)
 container_rows|tee "$OUT/containers-before.txt";if verify_containers;then pass "No restart required.";else action "Restart failed Microsoft Tunnel agent/server components and verify their state and health.";fi
 [[ $EXECUTE -eq 1 ]]||{ review "Preview only. Rerun with --execute to restart failed components.";package;exit 0;}
 read -rp 'Type RESTART-TUNNEL to continue: ' a;[[ "$a" == RESTART-TUNNEL ]]||exit 1
 agent_restart||true;server_restart||true;sleep 8;container_rows|tee "$OUT/containers-after.txt";verify_containers||true;;
upgrade)
 have curl||{ fail "curl unavailable";package;exit 1;};html="$OUT/update-history.html";curl -fsSL --max-time 60 "$UPGRADE_URL" -o "$html"
 python3 - "$html" "$OUT/latest.env" <<'PY'
import re,html,sys,shlex
x=html.unescape(re.sub('<[^>]+>',' ',open(sys.argv[1],errors='replace').read()));x=re.sub(r'\s+',' ',x)
p=re.compile(r'((?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, 20\d{2}).{0,500}?Version Number:\s*([0-9]{8}(?:\.[0-9]+)?(?:-[0-9]+)?).{0,700}?agentImageDigest\s*:?\s*(sha256:[0-9a-f]{64}).{0,500}?serverImageDigest\s*:?\s*(sha256:[0-9a-f]{64})',re.I)
m=p.search(x)
if not m:raise SystemExit('Latest release parse failed')
d,v,a,s=m.groups();open(sys.argv[2],'w').write('RELEASE_DATE='+shlex.quote(d)+'\nRELEASE_VERSION='+shlex.quote(v)+'\nTARGET_AGENT='+shlex.quote(a.lower())+'\nTARGET_SERVER='+shlex.quote(s.lower())+'\n')
PY
 source "$OUT/latest.env";current_agent="$(digest_get "$IMAGES" agentImageDigest)";current_server="$(digest_get "$IMAGES" serverImageDigest)"
 info "Latest release=$RELEASE_VERSION; date=$RELEASE_DATE";info "Installed agent=$current_agent";info "Installed server=$current_server";info "Target agent=$TARGET_AGENT";info "Target server=$TARGET_SERVER"
 msg="$OUT/images_configured.upgrade";cp "$IMAGES" "$msg"
 python3 - "$msg" "$TARGET_AGENT" "$TARGET_SERVER" <<'PY'
import re,sys
p,a,s=sys.argv[1:];t=open(p).read()
t,n1=re.subn(r'(agentImageDigest[^s]{0,120})sha256:[0-9a-fA-F]{64}',lambda m:m.group(1)+a,t,1,flags=re.I)
t,n2=re.subn(r'(serverImageDigest[^s]{0,120})sha256:[0-9a-fA-F]{64}',lambda m:m.group(1)+s,t,1,flags=re.I)
t,n3=re.subn(r'(mst_use_custom_image\s*[=:]\s*["\x27]?)[01]',lambda m:m.group(1)+'1',t,1,flags=re.I)
if (n1,n2)!=(1,1):raise SystemExit('Digest update failed')
open(p,'w').write(t)
PY
 action "Back up current state, start packet capture, submit latest-release message, monitor upgrade, stop capture, verify final digests and containers.";review "Force upgrade can interrupt Tunnel availability."
 [[ $EXECUTE -eq 1 ]]||{ review "Preview complete. Rerun with --execute to apply.";package;exit 0;}
 read -rp 'Type FORCE-UPGRADE-LATEST to continue: ' a;[[ "$a" == FORCE-UPGRADE-LATEST ]]||exit 1
 cp -p "$IMAGES" "$IMAGES.backup.$TS";[[ -r "$VERSION_INFO" ]]&&cp "$VERSION_INFO" "$OUT/version-info-before.json"
 start_capture "$OUT/upgrade.pcap"||review "Upgrade continues without packet capture"
 cp "$msg" "$MESSAGE_IN/images_configured.upgrade";pass "Upgrade message submitted"
 for ((i=0;i<MONITOR_SECONDS;i+=5));do printf '\r[EXECUTE] Monitoring upgrade %s/%s seconds' "$i" "$MONITOR_SECONDS";[[ ! -e "$MESSAGE_IN/images_configured.upgrade" ]]&&break;sleep 5;done;printf '\n'
 journalctl -t mstunnel_monitor --since "-$MONITOR_SECONDS seconds" --no-pager>"$OUT/upgrade-monitor.log" 2>&1||true;stop_capture
 [[ "$(digest_get "$IMAGES" agentImageDigest)" == "$TARGET_AGENT" ]]&&pass "Agent digest matches latest release"||fail "Agent digest does not match latest release"
 [[ "$(digest_get "$IMAGES" serverImageDigest)" == "$TARGET_SERVER" ]]&&pass "Server digest matches latest release"||fail "Server digest does not match latest release";verify_containers||true;;
network-trace)
 action "Start packet capture, reproduce the issue, press Enter when reproduction is complete, then stop capture and package evidence."
 [[ $EXECUTE -eq 1 ]]||{ review "Preview only. Rerun with --execute to capture.";package;exit 0;}
 read -rp 'Type NETWORK-TRACE to start capture: ' a;[[ "$a" == NETWORK-TRACE ]]||exit 1
 start_capture "$OUT/network-trace.pcap"||{ package;exit 1;}
 printf '\nPacket capture is RUNNING. Reproduce the VPN issue now.\n'
 read -rp 'When reproduction is complete, press Enter to stop capture: ' _
 stop_capture;pass "Packet capture stopped after administrator confirmed reproduction was complete";;
*)fail "Unknown scenario: $SCENARIO";package;exit 2;;esac
package
