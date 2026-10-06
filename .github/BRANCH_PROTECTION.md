# Recommended default-branch protection

Configure the default branch with these repository rules before public launch:

- require a pull request before merging;
- require at least one approving review;
- dismiss stale approvals after new commits;
- require review from CODEOWNERS for owned paths;
- require all review conversations to be resolved;
- require the branch to be up to date before merge;
- require successful CI and repository-policy checks;
- require linear history;
- block force pushes;
- block branch deletion;
- do not allow bypass for ordinary maintainer changes;
- use squash merge by default.

Security embargo branches are handled privately and merged only after review and
regression tests.
