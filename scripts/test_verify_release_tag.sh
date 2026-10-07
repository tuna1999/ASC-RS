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
  local label=$1 repo=$2 tag=$3 want=$4 got=0
  (cd "$repo" && bash "$verify" "$tag" >/dev/null 2>&1) || got=1
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

printf '\n%d passed, %d failed\n' "$pass" "$failed"
[ "$failed" = 0 ]
