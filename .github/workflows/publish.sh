#!/usr/bin/env bash

set -euo pipefail

package="secret_scan"
version="$(tr -d '[:space:]' < VERSION)"
tag="v${version}"

git config user.name "${GITHUB_ACTOR}"
git config user.email "${GITHUB_ACTOR}@users.noreply.github.com"

if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
  echo "${tag} already exists"
else
  git tag "${tag}"
  git push origin "${tag}"
fi

if mix hex.info "${package}" "${version}" >/dev/null 2>&1; then
  echo "${package} ${version} is already published"
else
  mix hex.publish --yes
fi
