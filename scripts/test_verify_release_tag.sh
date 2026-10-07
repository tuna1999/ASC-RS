#!/usr/bin/env bash
# Self-check for scripts/verify_release_tag.sh.
#
# Builds throwaway repositories that reproduce each ref shape the release
# workflow must accept or reject, and asserts the verifier's exit class.
# Run from anywhere: scripts/test_verify_release_tag.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
verify="$here/verify_release_tag.sh"
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

pass=0
failed=0

# expect <label> <repo> <tag> <accept|reject>
expect() {
  expect_script "$1" "$2" "$verify" "$3" "$4"
}

# expect_script <label> <repo> <verifier-script> <tag> <accept|reject>
expect_script() {
  local label=$1 repo=$2 script=$3 tag=$4 want=$5 got=0
  (cd "$repo" && bash "$script" "$tag" >/dev/null 2>&1) || got=1
  if [ "$want" = accept ]; then want=0; else want=1; fi
  if [ "$got" = "$want" ]; then
    printf 'ok    %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s: expected %s, exit status class %s\n' "$label" "$4" "$got" >&2
    failed=$((failed + 1))
  fi
}

repo="$root/repo"
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.email t@example.com
git -C "$repo" config user.name t
git -C "$repo" commit -q --allow-empty -m one

# `git rev-parse "<name>^{commit}"` also resolves branches, so a branch that
# looks like a release tag must NOT satisfy the verifier (this is the
# regression the namespaced lookup exists for).
echo 'version = "1.0.0"' >"$repo/Cargo.toml"
git -C "$repo" add Cargo.toml
git -C "$repo" commit -qm manifest
git -C "$repo" branch v1.0.0
expect "branch named v1.0.0 is not a tag" "$repo" v1.0.0 reject

echo 'version = "1.0.1"' >"$repo/Cargo.toml"
git -C "$repo" commit -qam v1.0.1
git -C "$repo" tag v1.0.1
expect "lightweight tag v1.0.1 at HEAD" "$repo" v1.0.1 accept

echo 'version = "1.0.2"' >"$repo/Cargo.toml"
git -C "$repo" commit -qam v1.0.2
git -C "$repo" tag -a v1.0.2 -m annotated
expect "annotated tag v1.0.2 at HEAD" "$repo" v1.0.2 accept

expect "nonexistent tag v1.0.3" "$repo" v1.0.3 reject

# Tag exists but the checkout is a later commit (a dispatch from the branch
# tip after the tag was cut).
git -C "$repo" commit -q --allow-empty -m after-tag
expect "HEAD past tag v1.0.1" "$repo" v1.0.1 reject

# Checkout is the tag's commit, but the manifest version disagrees.
echo 'version = "1.0.9"' >"$repo/Cargo.toml"
git -C "$repo" commit -qam bump
git -C "$repo" tag v1.0.4
expect "tag v1.0.4 vs Cargo.toml 1.0.9" "$repo" v1.0.4 reject

echo 'version = "1.0.5"' >"$repo/Cargo.toml"
git -C "$repo" commit -qam bump2
git -C "$repo" tag v1.0.5
expect "tag v1.0.5 matches Cargo.toml" "$repo" v1.0.5 accept

# --- Historical tag: the verifier comes from the workflow revision -------
#
# `refs/tags/v0.15.3` has no `scripts/verify_release_tag.sh` (the script
# first shipped in v0.15.4), so a re-release of that tag cannot run a
# verifier taken from the tag's own tree. The release workflow therefore
# stages the script from the revision that RUNS the workflow before it
# checks the target tag out. Reproduce both halves here: the in-tree
# invocation has nothing to run, the staged one verifies the tag.
hist="$root/hist"
mkdir -p "$hist"
git -C "$hist" init -q
git -C "$hist" config user.email t@example.com
git -C "$hist" config user.name t
echo 'version = "2.0.0"' >"$hist/Cargo.toml"
git -C "$hist" add Cargo.toml
git -C "$hist" commit -qm "release 2.0.0 (no scripts/)"
git -C "$hist" tag v2.0.0 # historical tag: verifier does not exist yet

# The control revision adds the verifier without moving the tag.
mkdir -p "$hist/scripts"
cp "$verify" "$hist/scripts/verify_release_tag.sh"
git -C "$hist" add scripts/verify_release_tag.sh
git -C "$hist" commit -qm "add release verifier"
staged="$root/staged-verify.sh"
cp "$hist/scripts/verify_release_tag.sh" "$staged" # workflow: cp → $RUNNER_TEMP

# Target checkout: exactly what actions/checkout does for the tag.
git -C "$hist" checkout -q refs/tags/v2.0.0
if (cd "$hist" && bash scripts/verify_release_tag.sh v2.0.0 >/dev/null 2>&1); then
  printf 'FAIL  historical tag: in-tree verifier unexpectedly ran\n' >&2
  failed=$((failed + 1))
else
  printf 'ok    historical tag: no in-tree verifier (pre-fix failure)\n'
  pass=$((pass + 1))
fi

# Staged verifier (run from the tag's working directory) accepts it.
expect_script "historical tag v2.0.0 via staged verifier" "$hist" "$staged" v2.0.0 accept

# And it still rejects a tag whose manifest disagrees, so the staged copy
# is the real verifier and not an accidentally-passing stub.
git -C "$hist" tag v2.0.1
expect_script "historical tag v2.0.1 vs Cargo.toml 2.0.0" "$hist" "$staged" v2.0.1 reject

printf '\n%d passed, %d failed\n' "$pass" "$failed"
[ "$failed" = 0 ]
