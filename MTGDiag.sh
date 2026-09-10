#!/usr/bin/env bash
# Microsoft Tunnel Intelligent Readiness & Diagnostics
# Owners: Anushka Rai and Yeswanth Kumar
set -Eeuo pipefail
IFS=$'\n\t'; umask 077
VERSION="7.4.1"
READY_URL="https://aka.ms/microsofttunnelready"
UPGRADE_URL="https://learn.microsoft.com/en-us/intune/device-security/microsoft-tunnel/upgrade#microsoft-tunnel-update-history"
MODE=""; SCENARIO=""; EXECUTE=0; INTERNAL_URL=""; TIMEOUT=8; MAX_ENDPOINTS=0; LOG_SINCE="-4 hours"; OUT=""; MONITOR_SECONDS=300; CAPTURE_INTERFACE="any"; CAPTURE_FILTER="port 443"; NON_INTERACTIVE=0; FORCE_COLOR=0; DISABLE_COLOR=0; HEALTH_WAIT_SECONDS=180
AGENT=/etc/mstunnel/AgentSettings.json; ADMIN=/etc/mstunnel/admin-settings.json; OCS=/etc/mstunnel/ocserv.conf; IMAGES=/etc/mstunnel/images_configured; VER=/etc/mstunnel/version-info.json; INBOX=/etc/mstunnel/messages/in
usage(){ cat <<'EOF'
Microsoft Tunnel Intelligent Readiness & Diagnostics v7.4.1
Usage: sudo ./MTGDiag.sh [options]

Modes:
  --mode full|inventory|connectivity|internal|troubleshoot|preview-all|self-test
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
# tee receives ANSI-free report output through a dedicated descriptor while the terminal gets color.
exec 3>>"$REPORT"
status_color(){ case "$1" in PASS)printf %s "$C_GREEN";;FAIL)printf %s "$C_RED";;REVIEW|SKIP)printf %s "$C_YELLOW";;ACTION)printf %s "$C_PURPLE";;INFO)printf %s "$C_BLUE";;*)printf %s "$C_RESET";;esac; }
pass(){ emit PASS "$1" "$2";};fail(){ emit FAIL "$1" "$2";};info(){ emit INFO "$1" "$2";};review(){ emit REVIEW "$1" "$2";};action(){ emit ACTION "$1" "$2";};skip(){ emit SKIP "$1" "$2";}
emit(){ local s="$1" i="$2" m="$3" c;c="$(status_color "$s")";printf '%s[%s]%s %s%s:%s %s\n' "$c" "$s" "$C_RESET" "$C_BOLD" "$i" "$C_RESET" "$m";printf '[%s] %s: %s\n' "$s" "$i" "$m" >&3;python3 - "$RESULTS" "$s" "$i" "$m" <<'PY'
import json,sys,datetime
p,s,i,m=sys.argv[1:];open(p,'a').write(json.dumps({'status':s,'id':i,'message':m,'time':datetime.datetime.now(datetime.timezone.utc).isoformat()})+'\n')
PY
}
phase(){ printf '\n%s%s[PHASE]%s %s\n' "$C_PURPLE" "$C_BOLD" "$C_RESET" "$1";printf '\n[PHASE] %s\n' "$1" >&3; }
redact(){ sed -E 's#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1<REDACTED>@#g;s/([Aa]uthorization:[[:space:]]*(Bearer|Basic))[[:space:]]+[^[:space:]]+/\1 <REDACTED>/g;s/(secret|password|passwd)=([^[:space:]]+)/\1=<REDACTED>/Ig'; }
json_get(){ local f="$1" k="$2";[[ -r "$f" ]]||return 0;if have jq;then jq -r --arg k "$k" '.[$k]//empty' "$f" 2>/dev/null;else sed -nE 's/.*"'"$k"'"[[:space:]]*:[[:space:]]*"?([^",}]*)"?.*/\1/p' "$f"|head -1;fi; }
digest_get(){ grep -Eio "$2[^s]{0,120}sha256:[0-9a-f]{64}" "$1" 2>/dev/null|grep -Eo 'sha256:[0-9a-f]{64}'|head -1||true; }
conf_values(){ awk -F= -v k="$1" 'BEGIN{IGNORECASE=1}$1~"^[[:space:]]*"k"[[:space:]]*$"{v=$0;sub(/^[^=]*=[[:space:]]*/,"",v);print v}' "$OCS" 2>/dev/null||true; }
ENGINE=none;have podman&&ENGINE=podman;[[ "$ENGINE" == none ]]&&have docker&&ENGINE=docker
container_rows(){ [[ "$ENGINE" != none ]]&&"$ENGINE" ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null|grep -Ei 'mstunnel|ocserv'||true; }
TCPDUMP_PID="";stop_capture(){ if [[ -n "$TCPDUMP_PID" ]]&&kill -0 "$TCPDUMP_PID" 2>/dev/null;then kill -INT "$TCPDUMP_PID" 2>/dev/null||true;wait "$TCPDUMP_PID" 2>/dev/null||true;fi;TCPDUMP_PID="";};trap stop_capture EXIT INT TERM
start_capture(){ local f="$1";have tcpdump||{ fail TRACE "tcpdump unavailable";return 1;};tcpdump -i "$CAPTURE_INTERFACE" -U -w "$f" $CAPTURE_FILTER>"$OUT/tcpdump.log" 2>&1 & TCPDUMP_PID=$!;sleep 2;kill -0 "$TCPDUMP_PID" 2>/dev/null||{ fail TRACE "tcpdump failed to start";return 1;};pass TRACE "Capture started; PID=$TCPDUMP_PID; interface=$CAPTURE_INTERFACE; filter=$CAPTURE_FILTER"; }
package(){ stop_capture;python3 - "$RESULTS" "$REPORT" "$OUT/report.html" "$VERSION" <<'PY'
import json,html,sys
j,t,o,v=sys.argv[1:];r=[]
for x in open(j):
 try:r.append(json.loads(x))
 except:pass
e=lambda x:html.escape(str(x));rows=''.join(f'<tr><td>{e(x["status"])}</td><td>{e(x["id"])}</td><td>{e(x["message"])}</td></tr>' for x in r)
open(o,'w').write(f'<html><head><meta charset="utf-8"><style>body{{font:14px Segoe UI;background:#f4f7fb}}main,section{{max-width:1400px;margin:15px auto;background:white;padding:18px}}table{{width:100%;border-collapse:collapse}}td{{padding:8px;border-bottom:1px solid #ddd}}pre{{white-space:pre-wrap}}</style></head><body><main><h1>Microsoft Tunnel Diagnostics v{v}</h1></main><section><table>{rows}</table></section><section><pre>{e(open(t,errors="replace").read())}</pre></section></body></html>')
PY
(cd "$OUT"&&find . -maxdepth 1 -type f ! -name evidence.tar.gz -print0|sort -z|xargs -0 sha256sum>SHA256SUMS)2>/dev/null||true;tar -C "$OUT" -czf "$OUT/evidence.tar.gz" --exclude evidence.tar.gz . 2>/dev/null||true;printf '\nReport: %s\nHTML: %s\nEvidence: %s\n' "$REPORT" "$OUT/report.html" "$OUT/evidence.tar.gz"; }
banner(){ printf '%s%s%s\n%s%s%s\n' "$C_BLUE" "================================================================================" "$C_RESET" "$C_BOLD" " MICROSOFT TUNNEL INTELLIGENT READINESS & DIAGNOSTICS" "$C_RESET"; printf '%s\n' " Version: $VERSION | Mode: ${MODE:-menu} | Scenario: ${SCENARIO:-none}" " Owners: Anushka Rai and Yeswanth Kumar" " Output: $OUT" "================================================================================"; }
preflight(){ phase "Runtime prerequisites";local miss=0 c;for c in bash python3 curl openssl tar awk sed grep sort find sha256sum timeout;do have "$c"&&pass "PRE-$c" available||{ fail "PRE-$c" missing;miss=1;};done;return "$miss"; }
supportability(){ [[ -r /etc/os-release ]]&&. /etc/os-release||true;local ev mm st=FAIL reason="Unsupported or unlisted OS/engine pair";ev="$([[ "$ENGINE" != none ]]&&$ENGINE --version 2>/dev/null||echo unavailable)";mm="$(printf %s "${VERSION_ID:-}"|grep -Eo '^[0-9]+\.[0-9]+'||true)";if [[ "${ID:-}" == ubuntu&&"$ENGINE" == docker&&( "$mm" == 24.04||"$mm" == 26.04 ) ]];then st=PASS;reason="Ubuntu $mm with Docker detected";elif [[ "${ID:-}" =~ rhel|redhat&&"$ENGINE" == podman ]];then st=PASS;reason="RHEL $mm with Podman detected; verify exact published Podman row";fi;emit "$st" SUPPORT "$reason | OS=${PRETTY_NAME:-unknown} | Engine=$ev"; }
container_log_snapshot(){
 local id="$1" name="$2" label="$3" file="$OUT/container-$name-health.log" driver logpath line source="none"
 driver="$($ENGINE inspect --format '{{.HostConfig.LogConfig.Type}}' "$id" 2>/dev/null || echo unknown)"
 logpath="$($ENGINE inspect --format '{{.LogPath}}' "$id" 2>/dev/null || true)"
 : > "$file"
 info "LOG-$name" "$label | LoggingDriver=$driver"
 if "$ENGINE" logs --timestamps --tail 80 "$id" >"$file" 2>"$file.error";then
   source="$ENGINE logs"
 elif [[ -n "$logpath" && "$logpath" != '<no value>' && -r "$logpath" ]];then
   tail -n 80 "$logpath" >"$file" 2>>"$file.error" || true;source="LogPath=$logpath"
 elif have journalctl;then
   journalctl --since "$LOG_SINCE" -t mstunnel_monitor -t mstunnel-agent -t ocserv --no-pager >"$file" 2>>"$file.error" || true;source="journalctl tags"
 fi
 if [[ -s "$file" ]];then
   info "LOG-$name" "LogSource=$source | Relevant recent log lines:"
   grep -Ei 'starting|started|healthy|ready|checkup|upgrade|pull|download|connect|register|error|fail|warn|timeout|certificate|proxy|dns' "$file" 2>/dev/null | tail -n 12 | while IFS= read -r line;do info "LOG-$name" "$line";done
 else
   review "LOG-$name" "Container log content is not locally readable with LoggingDriver=$driver. Health monitoring continues through container inspection and mst-cli status. See $file.error"
 fi
}


containers_health(){
 phase "Container status and health"
 local start_epoch now elapsed all_done id name status image health running role prev key final_bad=0
 local -A PREV=() FINAL=() IDS=() IMAGES_MAP=()
 start_epoch=$(date +%s)
 info CONTAINER-WAIT "Containers reporting health=starting will be monitored for up to ${HEALTH_WAIT_SECONDS}s before a final PASS or FAIL is assigned"
 while true;do
   all_done=1
   while IFS='|' read -r id name status image;do
     [[ -n "$id" ]]||continue;IDS["$name"]="$id";IMAGES_MAP["$name"]="$image"
     health="$($ENGINE inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-reported{{end}}' "$id" 2>/dev/null||echo unknown)"
     running=no;[[ "$status" =~ Up|running ]]&&running=yes
     key="$running|$health|$status"
     if [[ "${PREV[$name]:-}" != "$key" ]];then
       role=Container;[[ "$name" =~ mstunnel-agent ]]&&role=Agent;[[ "$name" =~ mstunnel-server|ocserv ]]&&role=Server
       if [[ "$running" == yes && "$health" == healthy ]];then pass "CONTAINER-$role" "Name=$name | Running=yes | Health=healthy | State=$status | Image=$image"
       elif [[ "$running" == yes && "$health" == starting ]];then review "CONTAINER-$role" "Name=$name | Running=yes | Health=starting | State=$status | Waiting for healthy"
       elif [[ "$running" == yes && "$health" == not-reported ]];then review "CONTAINER-$role" "Name=$name | Running=yes | Health=not-reported | State=$status"
       else fail "CONTAINER-$role" "Name=$name | Running=$running | Health=$health | State=$status | Image=$image";fi
       container_log_snapshot "$id" "$name" "State transition: ${PREV[$name]:-initial} -> $key";if have mst-cli;then [[ "$role" == Agent ]]&&mst-cli agent status >"$OUT/mst-cli-agent-status.txt" 2>&1||true;[[ "$role" == Server ]]&&mst-cli server status >"$OUT/mst-cli-server-status.txt" 2>&1||true;fi
       PREV["$name"]="$key"
     fi
     FINAL["$name"]="$key"
     [[ "$running" == yes && ( "$health" == healthy || "$health" == not-reported ) ]]||all_done=0
   done< <(container_rows)
   [[ ${#IDS[@]} -gt 0 ]]||{ fail CONTAINER "No Microsoft Tunnel containers were found";return 1;}
   now=$(date +%s);elapsed=$((now-start_epoch))
   [[ $all_done -eq 1 ]]&&break
   [[ $elapsed -ge $HEALTH_WAIT_SECONDS ]]&&break
   printf '\r[INFO] Waiting for Microsoft Tunnel containers to become healthy: %s/%ss' "$elapsed" "$HEALTH_WAIT_SECONDS"
   sleep 5
 done
 printf '\n'
 now=$(date +%s);elapsed=$((now-start_epoch))
 local found_agent=0 found_server=0
 for name in "${!IDS[@]}";do
   [[ "$name" =~ mstunnel-agent ]]&&found_agent=1
   [[ "$name" =~ mstunnel-server|ocserv ]]&&found_server=1
   IFS='|' read -r running health status <<<"${FINAL[$name]}"
   role=Container;[[ "$name" =~ mstunnel-agent ]]&&role=Agent;[[ "$name" =~ mstunnel-server|ocserv ]]&&role=Server
   if [[ "$running" == yes && "$health" == healthy ]];then pass "CONTAINER-$role-FINAL" "Name=$name reached healthy after ${elapsed}s | Image=${IMAGES_MAP[$name]}"
   elif [[ "$running" == yes && "$health" == not-reported ]];then review "CONTAINER-$role-FINAL" "Name=$name is running but health is not reported after ${elapsed}s"
   else fail "CONTAINER-$role-FINAL" "Name=$name did not become healthy within ${HEALTH_WAIT_SECONDS}s | Running=$running | Health=$health | State=$status";container_log_snapshot "${IDS[$name]}" "$name" "Final timeout/failure evidence";final_bad=1;fi
 done
 [[ $found_agent -eq 1 ]]||{ fail CONTAINER-Agent "Agent container not found";final_bad=1;}
 [[ $found_server -eq 1 ]]||{ fail CONTAINER-Server "Server container not found";final_bad=1;}
 [[ $final_bad -eq 0 ]]&&pass CONTAINER-SUMMARY "Agent and server container health validation completed successfully"||fail CONTAINER-SUMMARY "One or more Microsoft Tunnel containers failed final health validation"
 return "$final_bad"
}

proxy_checks(){ phase "Proxy configuration";{ env|grep -Ei '^(http|https|no)_proxy='||true;[[ -r /etc/mstunnel/env.sh ]]&&grep -Ei '(http|https|no)_proxy=' /etc/mstunnel/env.sh||true;systemctl show mstunnel_monitor -p Environment 2>/dev/null||true;}|redact>"$OUT/proxy-host.txt";grep -Eiq '(http|https)_proxy=' "$OUT/proxy-host.txt"&&pass PROXY-HOST "Host proxy configured; see proxy-host.txt"||info PROXY-HOST "No host HTTP/HTTPS proxy detected";if [[ "$ENGINE" == docker ]];then docker info 2>/dev/null|grep -Ei 'HTTP Proxy|HTTPS Proxy|No Proxy'|redact>"$OUT/proxy-engine.txt"||true;else podman info --format json 2>/dev/null|grep -Ei 'http_proxy|https_proxy|no_proxy'|redact>"$OUT/proxy-engine.txt"||true;fi;[[ -s "$OUT/proxy-engine.txt" ]]&&pass PROXY-ENGINE "$ENGINE engine proxy detected"||info PROXY-ENGINE "No $ENGINE engine proxy detected";local id n status image;while IFS='|' read -r id n status image;do "$ENGINE" inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null|grep -Ei '^(http|https|no)_proxy='|redact>"$OUT/proxy-$n.txt"||true;grep -Eiq '^(http|https)_proxy=' "$OUT/proxy-$n.txt"&&pass "PROXY-$n" configured||info "PROXY-$n" "No container HTTP/HTTPS proxy detected";done< <(container_rows); }
inventory(){ phase "Host and supportability";[[ -r /etc/os-release ]]&&. /etc/os-release||true;info HOST "${PRETTY_NAME:-unknown}; kernel=$(uname -r); arch=$(uname -m)";supportability;info RAM "$(free -h|awk '/Mem:/{print "Total=" $2 "; Used=" $3 "; Free=" $4 "; Available=" $7}')";info DISK "$(df -h /|awk 'NR==2{print "Total=" $2 "; Used=" $3 "; Available=" $4 "; Usage=" $5}')";[[ -e /dev/net/tun ]]&&pass TUN present||fail TUN missing;[[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null||echo 0)" == 1 ]]&&pass IPFORWARD enabled||fail IPFORWARD disabled;phase "Tunnel configuration";info ID "SiteId=$(json_get "$AGENT" SiteId); ServerId=$(json_get "$AGENT" ServerId); ConfigId=$(json_get "$AGENT" ConfigId)";info NETWORK "ClientNetwork=$(json_get "$ADMIN" Network); Effective=$(conf_values ipv4-network|head -1)";proxy_checks;containers_health; }
endpoints(){ phase "Required endpoint connectivity";local list="$OUT/endpoints.txt" src="$OUT/official-readiness.sh";curl -fsSL --max-time 60 "$READY_URL" -o "$src"||true;{ grep -Eo 'https?://[A-Za-z0-9._*-]+' "$src" 2>/dev/null|sed -E 's#https?://##';grep -Eo '([*]\.)?([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' "$src" 2>/dev/null;}|tr '[:upper:]' '[:lower:]'|sed -E 's#[/:].*$##'|grep -E '^([a-z0-9-]+\.)+[a-z]{2,24}$'|grep -Ev '^\*\.|\.(pem|crt|cer|key|json|conf|log|txt|sh|html)$'|sort -u>"$list";local total;total=$(wc -l<"$list");if [[ $MAX_ENDPOINTS -gt 0 ]];then head -n "$MAX_ENDPOINTS" "$list">"$list.tmp";mv "$list.tmp" "$list";review CONN-LIMIT "Testing first $MAX_ENDPOINTS of $total endpoints";fi;total=$(wc -l<"$list");[[ $total -gt 0 ]]||{ fail CONN-EMPTY "No endpoints discovered";return;};probe_scope(){ local type="$1" cid="$2" name="$3" host rc dns out http n=0 timing issuer tlsver;while read -r host;do ((++n));rc=0;dns=PASS;out="$OUT/.conn.$$";if [[ "$type" == host ]];then getent hosts "$host">/dev/null||dns=FAIL;curl -sSvI --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w '%{time_connect}|%{time_appconnect}|%{time_total}|%{ssl_verify_result}' "https://$host/" -o /dev/null 2>"$out" >"$out.time"||rc=$?;else "$ENGINE" exec "$cid" getent hosts "$host">/dev/null 2>&1||dns=FAIL;"$ENGINE" exec "$cid" sh -c 'curl -sSvI --connect-timeout "$1" --max-time "$1" -w "%{time_connect}|%{time_appconnect}|%{time_total}|%{ssl_verify_result}" "https://$2/" -o /dev/null' sh "$TIMEOUT" "$host" 2>"$out" >"$out.time"||rc=$?;fi;http="$(grep -E '^< HTTP/' "$out"|tail -1|awk '{print $3}'||true)";timing="$(cat "$out.time" 2>/dev/null||echo 'n/a|n/a|n/a|n/a')";issuer="$(grep -im1 'issuer:' "$out"|sed 's/^[* ]*//'||true)";tlsver="$(grep -Eim1 'SSL connection using|TLSv1\.[23]' "$out"|sed 's/^[* ]*//'||true)";IFS='|' read -r tcp_time tls_time total_time verify_result <<<"$timing";[[ $rc -eq 0 ]]&&pass "CONN-$name-$n" "$host; DNS=$dns; TCP=${tcp_time}s; TLS=${tls_time}s; Total=${total_time}s; Verify=${verify_result}; HTTP=${http:-response}; Protocol=${tlsver:-unknown}; ${issuer:-Issuer=unknown}"||fail "CONN-$name-$n" "$host; DNS=$dns; TCP=${tcp_time}s; TLS=${tls_time}s; Total=${total_time}s; exit=$rc";rm -f "$out" "$out.time";done<"$list";pass "CONN-$name-SUMMARY" "Completed $n/$total endpoints";};probe_scope host '' Host;local id n status image;while IFS='|' read -r id n status image;do "$ENGINE" exec "$id" sh -c 'command -v curl >/dev/null' 2>/dev/null&&probe_scope container "$id" "$n"||skip "CONN-$n" "curl unavailable";done< <(container_rows); }
internal_test(){ phase "Internal application connectivity";if [[ ! "$INTERNAL_URL" =~ ^https?:// ]];then if [[ $NON_INTERACTIVE -eq 1||! -t 0 ]];then skip INTERNAL "No internal URL supplied";return;fi;read -rp 'Internal access-check URL (Enter to skip): ' INTERNAL_URL;[[ -n "$INTERNAL_URL" ]]||{ skip INTERNAL "Skipped by administrator";return;};fi;local id n status image rc out;while IFS='|' read -r id n status image;do rc=0;out="$OUT/internal-$n.log";"$ENGINE" exec "$id" sh -c 'curl -sSvI --connect-timeout "$1" --max-time "$1" "$2" -o /dev/null' sh "$TIMEOUT" "$INTERNAL_URL">/dev/null 2>"$out"||rc=$?;[[ $rc -eq 0 ]]&&pass "INTERNAL-$n" "$INTERNAL_URL reachable"||fail "INTERNAL-$n" "$INTERNAL_URL failed; exit=$rc";done< <(container_rows); }
certificate(){ phase "Tunnel public TLS certificate";local cert="$OUT/active.crt" path;path="$(awk -F= 'BEGIN{IGNORECASE=1}$1~/^[[:space:]]*server-cert[[:space:]]*$/{v=$0;sub(/^[^=]*=[[:space:]]*/,"",v);gsub(/"/,"",v);print v;exit}' "$OCS" 2>/dev/null||true)";for f in "$path" "/etc/mstunnel/certs/$path" /etc/mstunnel/certs/ocserv-active.crt;do [[ -r "$f" ]]&&openssl x509 -in "$f" -noout>/dev/null 2>&1&&{ cp "$f" "$cert";break;};done;[[ -s "$cert" ]]||timeout "$TIMEOUT" openssl s_client -connect 127.0.0.1:443 -showcerts </dev/null 2>/dev/null|awk '/BEGIN CERTIFICATE/{x=1}x{print}/END CERTIFICATE/{exit}'>"$cert"||true;openssl x509 -in "$cert" -noout>/dev/null 2>&1||{ review CERT "Active certificate not located";return;};openssl x509 -in "$cert" -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName -ext keyUsage -ext extendedKeyUsage -ext authorityInfoAccess -ext crlDistributionPoints>"$OUT/certificate.txt" 2>&1||true;pass CERT "Certificate parsed successfully";while IFS= read -r certline;do info CERT-DETAIL "$certline";done<"$OUT/certificate.txt";local key bits sig policy st=REVIEW reason="Compatibility not determined";key="$(openssl x509 -in "$cert" -noout -text|awk -F: '/Public Key Algorithm/{gsub(/^[ ]+/,"",$2);print $2;exit}')";bits="$(openssl x509 -in "$cert" -noout -text|sed -nE 's/^[[:space:]]*Public-Key: \(([0-9]+) bit\).*/\1/p'|head -1)";sig="$(openssl x509 -in "$cert" -noout -text|awk -F: '/Signature Algorithm/{gsub(/^[ ]+/,"",$2);print $2;exit}')";policy="$(conf_values tls-priorities|head -1)";if echo "$key"|grep -Eqi 'rsa';then if [[ -n "$bits"&&"$bits" -lt 2048 ]]||echo "$sig"|grep -Eqi 'sha1|md5';then st=FAIL;reason="Unsupported weak RSA/signature";elif echo "$policy"|grep -q 'ECDHE-RSA';then st=PASS;reason="RSA certificate compatible with ECDHE-RSA policy";fi;elif echo "$key"|grep -Eqi 'ecPublicKey';then echo "$policy"|grep -q 'ECDHE-ECDSA'&&{ st=PASS;reason="ECDSA compatible";}||{ st=FAIL;reason="ECDSA certificate but ECDHE-ECDSA absent";};fi;emit "$st" CERT-ALGORITHM "$reason; Key=$key/$bits; Signature=$sig";info CERT-POLICY "tls-priorities=${policy:-not found}";echo "$policy"|grep -q 'VERS-TLS1.2'&&pass TLS12 "TLS 1.2 enabled by effective policy"||review TLS12 "TLS 1.2 not confirmed in effective policy";echo "$policy"|grep -q 'VERS-TLS1.3'&&pass TLS13 "TLS 1.3 enabled by effective policy"||review TLS13 "TLS 1.3 not confirmed in effective policy";echo "$policy"|grep -q 'AES-256-GCM'&&pass CIPHER "AES-256-GCM enabled by effective policy"||review CIPHER "AES-256-GCM not confirmed in effective policy";grep -Eo '(https?|ldap|ldaps)://[^[:space:]]+' "$OUT/certificate.txt"|sed -E 's/[),]$//'|sort -u>"$OUT/revocation-urls.txt"||true;while read -r u;do [[ -n "$u" ]]&&info REVOCATION "$u";done<"$OUT/revocation-urls.txt"; }
release_map(){ phase "Installed image version";local a s html json;a="$(digest_get "$IMAGES" agentImageDigest)";s="$(digest_get "$IMAGES" serverImageDigest)";info DIGEST "Agent=$a; Server=$s";html="$OUT/update-history.html";json="$OUT/release.json";curl -fsSL --max-time 60 "$UPGRADE_URL" -o "$html"||{ review RELEASE "Update history unavailable";return;};python3 - "$html" "$json" "$a" "$s" <<'PY'
import re,html,json,sys
x=html.unescape(re.sub('<[^>]+>',' ',open(sys.argv[1],errors='replace').read()));x=re.sub(r'\s+',' ',x);p=re.compile(r'((?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, 20\d{2}).{0,500}?Version Number:\s*([0-9]{8}(?:\.[0-9]+)?(?:-[0-9]+)?).{0,700}?agentImageDigest\s*:?\s*(sha256:[0-9a-f]{64}).{0,500}?serverImageDigest\s*:?\s*(sha256:[0-9a-f]{64})',re.I);r=[{'date':d,'version':v,'agent':a.lower(),'server':s.lower()} for d,v,a,s in p.findall(x)];m=next((z for z in r if z['agent']==sys.argv[3] and z['server']==sys.argv[4]),None);json.dump({'latest':r[0] if r else None,'installed':m},open(sys.argv[2],'w'),indent=2);print(json.dumps({'latest':r[0] if r else None,'installed':m}))
PY
 local line;line="$(cat "$json")";info RELEASE "Mapping saved to release.json";rm -f "$html"; }

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
 release_map
 local latest installed islatest
 mapfile -t x < <(python3 - "$OUT/release.json" <<'PYR'
import json,sys
x=json.load(open(sys.argv[1]));l=x.get('latest') or {};i=x.get('installed') or {}
print(l.get('version',''));print(l.get('date',''));print(i.get('version',''));print(i.get('date',''));print('true' if l and i and l==i else 'false')
PYR
 )
 if [[ "${x[4]}" == true ]];then pass RELEASE-HEALTH "Healthy: installed digest pair matches latest release ${x[0]}, released ${x[1]}";elif [[ -n "${x[2]}" ]];then review RELEASE-HEALTH "Installed release=${x[2]} (${x[3]}); latest=${x[0]} (${x[1]})";else fail RELEASE-HEALTH "Installed digest pair is not found in published history; latest=${x[0]} (${x[1]})";fi
}

preview_all(){
 phase "Preview everything"
 info PREVIEW-ALL "Running full diagnostics and every troubleshooting workflow in preview mode"
 inventory;endpoints;internal_test;certificate;revocation_checks;release_health
 local old="$SCENARIO";EXECUTE=0
 for SCENARIO in unhealthy ip-starvation bridge-conflict container-down upgrade network-trace;do troubleshoot;done
 SCENARIO="$old";pass PREVIEW-ALL "All diagnostics and scenario previews completed; no remediation executed"
}

latest_release_values(){
 local json="$OUT/release.json"
 [[ -s "$json" ]]||release_map
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
 release_health
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

main_menu(){ cat <<'EOF'
Select an operation:
  1) Full diagnostics
  2) Inventory and certificate assessment
  3) Required endpoint connectivity
  4) Internal application connectivity
  5) Guided troubleshooting
  6) Preview everything: full diagnostics and all troubleshooting previews
  7) Production self-test
  0) Exit
EOF
read -rp 'Selection [0-7]: ' x;case "$x" in 1)MODE=full;;2)MODE=inventory;;3)MODE=connectivity;;4)MODE=internal;;5)MODE=troubleshoot;;6)MODE=preview-all;;7)MODE=self-test;;0)exit 0;;*)exit 2;;esac; }
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
 unhealthy)state="$(json_get "$AGENT" CurrentServerHealthStatus)";info HEALTH "CurrentServerHealthStatus=$state";[[ "$state" == 1 ]]&&pass HEALTH "Already healthy"||action HEALTH "Back up AgentSettings, set health to 1, restart agent, verify";[[ $EXECUTE -eq 1&&"$state" != 1 ]]||return;read -rp 'Type RESET-TUNNEL-HEALTH: ' a;[[ "$a" == RESET-TUNNEL-HEALTH ]]||return;cp -p "$AGENT" "$AGENT.backup.$TS";python3 - "$AGENT" <<'PY'
import json,sys,tempfile,os
p=sys.argv[1];d=json.load(open(p));d['CurrentServerHealthStatus']=1;fd,t=tempfile.mkstemp(dir=os.path.dirname(p));os.close(fd);json.dump(d,open(t,'w'),indent=2);os.replace(t,p)
PY
restart_agent;sleep 5;containers_health;;
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
 container-down)containers_health;[[ $EXECUTE -eq 1 ]]||{ review CONTAINER "Preview only; add --execute";return;};read -rp 'Type RESTART-TUNNEL: ' a;[[ "$a" == RESTART-TUNNEL ]]||return;restart_agent||true;restart_server||true;sleep 8;containers_health;;
 upgrade)force_upgrade_latest;;
 network-trace)action TRACE "Start capture, reproduce issue, press Enter, stop and package";[[ $EXECUTE -eq 1 ]]||{ review TRACE "Preview only; add --execute";return;};read -rp 'Type NETWORK-TRACE: ' a;[[ "$a" == NETWORK-TRACE ]]||return;start_capture "$OUT/network-trace.pcap"||return;echo 'Capture RUNNING. Reproduce issue now.';read -rp 'Press Enter when reproduction is complete: ' _;stop_capture;pass TRACE "Capture stopped";;
 *)fail TROUBLESHOOT "Unknown scenario";;esac; }
[[ -n "$MODE"||-n "$SCENARIO" ]]||main_menu;[[ -n "$SCENARIO"&&-z "$MODE" ]]&&MODE=troubleshoot
banner
preflight||{ package;exit 2;}
case "$MODE" in
 full)inventory;endpoints;internal_test;certificate;revocation_checks;release_health;;
 inventory)inventory;certificate;revocation_checks;release_health;; connectivity)inventory;endpoints;; internal)inventory;internal_test;; troubleshoot)troubleshoot;; preview-all)preview_all;; self-test)pass SELFTEST "Runtime prerequisites verified";; *)fail MODE "Invalid mode: $MODE";;esac
package
