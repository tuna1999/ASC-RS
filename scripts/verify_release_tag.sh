#!/usr/bin/env bash
# Fail unless the current checkout really is the release tag's commit.
#
# `git rev-parse "<name>^{commit}"` does NOT prove <name> is a tag: git's
# short-name lookup also searches refs/heads, so a *branch* called `v9.9.9`
# resolves through the very same expression. A manual `workflow_dispatch`
# from such a branch would then "verify" itself and publish branch HEAD
# under the tag's name. Every lookup below is namespace-qualified instead.
#
# Usage: scripts/verify_release_tag.sh <tag> [cargo-toml]
set -euo pipefail

tag=${1:?usage: $0 <tag> [cargo-toml]}
manifest=${2:-Cargo.toml}

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

git show-ref --verify --quiet "refs/tags/${tag}" \
  || fail "${tag} is not a tag: refs/tags/${tag} does not exist"

tag_sha=$(git rev-parse --verify "refs/tags/${tag}^{commit}") \
  || fail "refs/tags/${tag} does not resolve to a commit"

head_sha=$(git rev-parse HEAD)
[ "$head_sha" = "$tag_sha" ] \
  || fail "checked out ${head_sha} but refs/tags/${tag} is ${tag_sha}"

# The tag names the release, the manifest names the build: they must agree,
# or the released binaries would carry a version the tag does not claim.
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$manifest" | head -n 1)
[ -n "$version" ] || fail "no version found in ${manifest}"
[ "v${version}" = "$tag" ] \
  || fail "release tag ${tag} does not match ${manifest} version v${version}"

printf 'release source verified: %s -> %s\n' "$tag" "$head_sha"
