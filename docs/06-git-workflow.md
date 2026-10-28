# 06 — Git workflow (how we avoid merge conflicts)

## The one rule

**You only edit your own folders.** If two people never touch the same file, git can't conflict.
Ownership is in `AGENTS.md` section 2 and enforced by `.github/CODEOWNERS`.

## Setup (once)

- Repo: `github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08` (private, event org). Collaborators: `jrush-vj` (Jerush), `AbhiNav-S-Biju` (Abhinav), `AkchhatGrg` (Akchhat).
- `main` is protected: PRs only, 1 approval (from Jerush), no force-push.

## Daily loop

```bash
git checkout main && git pull
git checkout -b feat/<you>-<thing>        # e.g. feat/akchhat-honeypot-routes
# ... work only inside your folders ...
git add <your-folder>/
git commit -m "honeypot: mirror transfer and search routes"
git fetch origin && git rebase origin/main
git push -u origin feat/<you>-<thing>
# open a PR on GitHub using the template
```

- Keep branches short-lived: open a PR at least every 2–3 hours.
- Use `git add <your-folder>/`, never `git add .` (it stops you committing someone else's files by accident).
- If a rebase conflicts, you probably edited a file you don't own. Undo that change and ask the owner.

## When you need something outside your folders

| Need | Do |
|---|---|
| A new field in an event or rule | Write it under "Requests to Jerush" in your `team/<NAME>.md`, plus a message in the group chat |
| A new env var or compose change | Same as above |
| A new bank route, or a change to one (Abhinav) | Ask Akchhat |
| A change to the gateway's behaviour (Akchhat) | Ask Abhinav |

The owner makes the change in their own PR. You rebase once it's merged.

## Gates

At each gate (see `docs/05-phases-and-gates.md`):

1. Everyone pushes and opens PRs by the gate hour.
2. Jerush merges them in this order: `shared/` changes, then Abhinav, then Akchhat, then Jerush's services.
3. Jerush runs the e2e tests and tags the commit.
4. Everyone runs `git pull --rebase` on `main` before continuing.

## Never commit

`.env`, API keys, Cloudflare tokens, `*.db`, `node_modules/`, model files (`*.gguf`), `__pycache__/`.
The `.gitignore` (Jerush) covers these.
