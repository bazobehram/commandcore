#!/bin/sh
# Fast-forward-only staging branch publication; no production deployment.
set -eu
cd "$(dirname "$0")/.."
branch=codex/p0-compatibility-integration
expected_parent=bc6268b08d754d57d5cfb2725cc89e44e81a41da
expected_commit=$(git -c safe.directory="$PWD" rev-parse HEAD)
git -c safe.directory="$PWD" branch --show-current | grep -Fx "$branch"
test "$(git -c safe.directory="$PWD" rev-parse HEAD^)" = "8dec8d70c4f40c0e180d26a16db794fc11677f0d"
test "$(git -c safe.directory="$PWD" rev-parse HEAD^^)" = "$expected_parent"
test "$(git -c safe.directory="$PWD" rev-parse origin/"$branch")" = "$expected_parent"
git -c safe.directory="$PWD" diff-tree --no-commit-id --name-only -r HEAD^ | grep -q '^apps/server/commandcore_server/collaboration_'
test -x scripts/collaboration_staged_acceptance.sh
./scripts/collaboration_staged_acceptance.sh > /tmp/cc-publish-preflight.log 2>&1
GH_PROMPT_DISABLED=1 gh auth status >/dev/null
git -c safe.directory="$PWD" -c credential.helper='!gh auth git-credential' fetch origin "+refs/heads/$branch:refs/remotes/origin/$branch"
test "$(git -c safe.directory="$PWD" rev-parse origin/"$branch")" = "$expected_parent"
git -c safe.directory="$PWD" -c credential.helper='!gh auth git-credential' push origin "$expected_commit:refs/heads/$branch"
echo "RELEASE_CANDIDATE_BRANCH_PUSHED=$expected_commit"
