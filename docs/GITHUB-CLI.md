# GitHub CLI Cheat Sheet

Practical [`gh`](https://cli.github.com/) commands for working with this repository —
checking status, running the pipeline, and shipping changes via pull request.

## Check status

```bash
gh auth status          # are you logged in? which account / token scopes
gh pr status            # PRs relevant to you in this repo (yours, review requests)
gh run list -L 5        # recent GitHub Actions (CI) runs and their result
gh run watch            # live-follow the currently running workflow until it finishes
gh pr checks <number>   # CI check results for a specific PR
gh repo view            # repo overview (description, README) in the terminal
gh status               # cross-repo dashboard: assignments, mentions, review requests
```

> `gh` reports **your repo/CI/auth** status. Whether GitHub itself is up lives at
> [githubstatus.com](https://www.githubstatus.com/) — there is no `gh` command for it.

## Ship a change via pull request

The repository keeps `main` protected-by-convention: branch, push, open a PR, let CI
pass, then merge. This is the exact flow used in this repo.

```bash
# 1. Branch off an up-to-date main
git checkout main
git pull origin main
git checkout -b feat/my-change

# 2. Commit your work (the pre-commit hook runs lint/typecheck/unit tests)
git add <files>
git commit -m "Describe the change"

# 3. Push the branch and open a PR against main
git push -u origin feat/my-change
gh pr create --title "My change" --body "What and why"

# 4. Watch CI, then merge once green
gh pr checks            # or: gh run watch
gh pr merge <number> --squash --delete-branch
```

### Merge styles

| Command                                    | Result                                       |
| ------------------------------------------ | -------------------------------------------- |
| `gh pr merge <n> --squash --delete-branch` | One clean commit on `main` (recommended)     |
| `gh pr merge <n> --merge --delete-branch`  | Keeps every commit plus a merge commit       |
| `gh pr merge <n> --rebase --delete-branch` | Replays commits onto `main`, no merge commit |

> `gh pr merge <n>` with **no** method flag opens an interactive menu to pick the style.

### After merging

`gh pr merge --delete-branch` fast-forwards and switches your local `main` for you, so a
manual sync is usually a no-op — but it is a good habit to confirm:

```bash
git checkout main
git pull origin main
```

## Useful one-offs

```bash
gh pr view <number> --web          # open a PR in the browser
gh pr list                         # list open PRs
gh run rerun <run-id>              # re-run a failed CI workflow
gh workflow run audit.yml -f fail_on=High   # manually dispatch the audit with a gate
```
