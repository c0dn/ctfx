#!/usr/bin/env bash
# Prints the next release version (without "v") from conventional commits
# since the last v* tag: breaking -> major (minor while < 1.0), feat -> minor,
# anything else -> patch. Versions already tagged or published to npm are
# skipped, since npm never allows reusing a version.
set -euo pipefail

last="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
range="${last:+$last..}HEAD"
IFS=. read -r major minor patch <<<"${last#v}"
major="${major:-0}" minor="${minor:-0}" patch="${patch:-0}"

log="$(git log --format='%s%n%b' "$range")"
if grep -qE '^[a-z]+(\([^)]*\))?!:|^BREAKING[ -]CHANGE' <<<"$log"; then
  bump=breaking
elif grep -qE '^feat(\([^)]*\))?:' <<<"$log"; then
  bump=feat
else
  bump=patch
fi

case "$bump" in
  breaking) if [ "$major" -eq 0 ]; then minor=$((minor + 1)); patch=0; else major=$((major + 1)); minor=0; patch=0; fi ;;
  feat) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac

# The registry's "time" map keeps unpublished versions, which cannot be reused.
npm_times=""
if [ -n "${NPM_PACKAGE:-}" ]; then
  npm_times="$(npm view "$NPM_PACKAGE" time --json 2>/dev/null || true)"
fi
taken() {
  git rev-parse -q --verify "refs/tags/v$1" >/dev/null || grep -q "\"$1\":" <<<"$npm_times"
}
while taken "$major.$minor.$patch"; do patch=$((patch + 1)); done
echo "$major.$minor.$patch"
