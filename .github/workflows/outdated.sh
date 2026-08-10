#!/usr/bin/env bash

set -euo pipefail

branch="update-gitleaks-rules"

bump_version() {
  awk -F. '{printf("%d.%d.%d\n", $1, $2, $3 + 1) > "VERSION"}' VERSION
}

open_pr_count() {
  gh pr list --state open --head "${branch}" --json number --jq length
}

git config user.name "${GITHUB_ACTOR}"
git config user.email "${GITHUB_ACTOR}@users.noreply.github.com"

open_pr="$(open_pr_count)"
remote_branch=0

if git fetch origin "refs/heads/${branch}:refs/remotes/origin/${branch}"; then
  remote_branch=1
fi

if [[ "${open_pr}" -gt 0 && "${remote_branch}" -eq 1 ]]; then
  git checkout -B "${branch}" "origin/${branch}"
  git rebase origin/main
else
  git checkout -B "${branch}" origin/main
fi

set +e
mix secret_scan.refresh --check-outdated
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  exit 0
fi

if [[ "${status}" -ne 100 ]]; then
  exit "${status}"
fi

mix secret_scan.refresh

if [[ "${open_pr}" -eq 0 ]]; then
  bump_version
fi

git add README.md VERSION rules
git commit -m "Update Gitleaks rules"
git push --force-with-lease --set-upstream origin "${branch}"

if [[ "${open_pr}" -eq 0 ]]; then
  gh pr create --title "Update Gitleaks rules" --body-file .github/workflows/outdated-pr.md
fi
