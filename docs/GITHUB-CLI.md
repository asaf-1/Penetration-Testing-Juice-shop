# GitHub CLI Cheat Sheet

Practical [`gh`](https://cli.github.com/) commands for working with this repository —
checking status, running the pipeline, and shipping changes via pull request. Every
command below has a short inline note on what it does.

## Check status

```bash
gh auth status          # are you logged in? which account / token scopes
gh pr status            # PRs relevant to you in this repo (yours, review requests)
gh run list -L 5        # list the 5 most recent GitHub Actions (CI) runs and their result
gh run watch            # live-follow the currently running workflow until it finishes
gh pr checks <number>   # show the CI check results for a specific PR
gh repo view            # print the repo overview (description, README) in the terminal
gh status               # cross-repo dashboard: assignments, mentions, review requests
```

> `gh` reports **your repo/CI/auth** status. Whether GitHub itself is up lives at
> [githubstatus.com](https://www.githubstatus.com/) — there is no `gh` command for it.

## Ship a change via pull request

The repository keeps `main` protected: branch, push, open a PR, let CI pass, then merge.
This is the exact flow used in this repo.

```bash
git checkout main                   # switch to the main branch
git pull origin main                # update main to the latest remote state
git checkout -b feat/my-change      # create and switch to a new feature branch

git add <files>                     # stage the files you changed
git commit -m "Describe the change" # commit them (pre-commit hook runs lint/typecheck/unit tests)

git push -u origin feat/my-change   # push the branch and set it to track origin
gh pr create --fill                 # open a PR against main, reusing the commit message
gh pr create --title "T" --body "B" # ...or open a PR with a custom title/body instead

gh pr checks                        # show CI results for the current branch's PR
gh pr merge <n> --squash --delete-branch  # squash-merge once green, then delete the branch
```

### Merge styles

| Command                                    | Result                                       |
| ------------------------------------------ | -------------------------------------------- |
| `gh pr merge <n> --squash --delete-branch` | One clean commit on `main` (recommended)     |
| `gh pr merge <n> --merge --delete-branch`  | Keeps every commit plus a merge commit       |
| `gh pr merge <n> --rebase --delete-branch` | Replays commits onto `main`, no merge commit |

> `gh pr merge <n>` with **no** method flag opens an interactive menu to pick the style.

### When the merge is blocked by branch protection

`main` is a protected branch: a required check (`Lint, Typecheck & Unit Tests`) must pass
before a merge is allowed. If you run `gh pr merge` while CI is still running, you'll get
`not mergeable: the base branch policy prohibits the merge`. That is the rule working —
not an error. Pick one:

```bash
gh pr merge <n> --squash --delete-branch --auto   # auto-merge: fires automatically once all required checks pass (recommended)
gh pr checks <n> --watch                          # block in the terminal until every check finishes, then merge manually
gh pr merge <n> --squash --delete-branch --admin  # admin override: merge now with repo-admin rights, bypassing the wait (use sparingly)
```

### After merging

```bash
git checkout main      # return to the main branch
git pull origin main   # pull the just-merged commit (often a no-op — --delete-branch already syncs you)
```

## Useful one-offs

```bash
gh pr view <number> --web                  # open a PR in the browser
gh pr list                                 # list open PRs in this repo
gh pr diff <number>                         # show a PR's diff in the terminal
gh run rerun <run-id>                      # re-run a failed CI workflow
gh run view <run-id> --log-failed          # print only the failed steps' logs of a run
gh workflow run audit.yml -f fail_on=High  # manually dispatch the audit with a severity gate
```
