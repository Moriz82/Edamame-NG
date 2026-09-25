#!/usr/bin/env bash
# Run only inside an explicitly disposable, unprivileged LXC guest.
set -euo pipefail

[[ ${EDAMAME_DISPOSABLE_LXC:-} == 1 && $EUID == 0 && $# == 1 ]] || exit 77
[[ $(systemd-detect-virt -c 2>/dev/null) == lxc ]] || exit 77
read -r inside outside _ < /proc/self/uid_map
[[ $inside == 0 && $outside != 0 ]] || exit 77
runner=$1
[[ -f $runner && -x /usr/bin/find && ! -u /usr/bin/find ]] || exit 77
[[ $(stat -Lc %u /usr/bin/find) == 0 ]] || exit 77

original_mode=$(stat -Lc %a /usr/bin/find)
fixture=$(mktemp -d /tmp/edamame-suid-find.XXXXXX)
cleanup() {
  chown root:root /usr/bin/find
  chmod "$original_mode" /usr/bin/find
  [[ $fixture == /tmp/edamame-suid-find.* ]] && rm -r -- "$fixture"
}
trap cleanup EXIT

chmod 755 "$fixture"
mkdir -p "$fixture"/{home,cache,runs,assets,catalog}
chown -R "nobody:$(id -gn nobody)" "$fixture/home" "$fixture/cache" "$fixture/runs"
chmod 700 "$fixture/home" "$fixture/cache" "$fixture/runs"
printf 'cve\tplatform\tproduct\tkev_date\treference\n' > "$fixture/catalog/local-eop.tsv"
for name in linpeas lse; do
  cat > "$fixture/assets/$name.sh" <<EOF
#!/bin/sh
printf 'run\n' >> '$fixture/invocations'
printf 'fixture output\n'
EOF
  chmod 755 "$fixture/assets/$name.sh"
  sha256sum "$fixture/assets/$name.sh" | cut -d ' ' -f1 > "$fixture/assets/$name.sh.sha256"
done
touch "$fixture/invocations"
chown nobody:"$(id -gn nobody)" "$fixture/invocations"

run_as_nobody() {
  local cmd
  printf -v cmd '%q ' env "HOME=$fixture/home" "XDG_CACHE_HOME=$fixture/cache" bash "$runner" \
    "$@" --output-dir "$fixture/runs" --tool-dir "$fixture/assets" --catalog-dir "$fixture/catalog"
  su -s /bin/bash nobody -c "$cmd"
}

run_as_nobody --scan --no-shell > "$fixture/baseline.log"
[[ $(find "$fixture/runs" -mindepth 1 -maxdepth 1 -type d | wc -l) == 1 ]]
[[ $(wc -l < "$fixture/invocations") == 2 ]]
! find "$fixture/runs" -name success.tsv | grep -q .

chmod u+s /usr/bin/find
run_as_nobody --scan --no-shell > "$fixture/fixture.log"
[[ $(find "$fixture/runs" -mindepth 1 -maxdepth 1 -type d | wc -l) == 2 ]]
success=$(find "$fixture/runs" -name success.tsv -print -quit)
[[ -n $success ]]
awk -F '\t' '$2=="suid-find" {found=1} END {exit !found}' "$success"
[[ $(wc -l < "$fixture/invocations") == 4 ]]

run_as_nobody --resume --no-shell > "$fixture/resume.log"
grep -q '\[RESUME\] suid-find' "$fixture/resume.log"
[[ $(wc -l < "$fixture/invocations") == 4 ]]

chmod "$original_mode" /usr/bin/find
if run_as_nobody --resume --no-shell > "$fixture/no-suid.log" 2>&1; then exit 1; fi
grep -q 'no longer works' "$fixture/no-suid.log"

chown "nobody:$(id -gn nobody)" /usr/bin/find
chmod u+s /usr/bin/find
if run_as_nobody --resume --no-shell > "$fixture/wrong-owner.log" 2>&1; then exit 1; fi
grep -q 'no longer works' "$fixture/wrong-owner.log"

printf 'SUID find Scan, Resume, enumeration skip, and prerequisite-loss checks passed\n'
