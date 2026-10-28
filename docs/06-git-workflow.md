# 06 — Git workflow (how we avoid merge conflicts)

## The one rule

**You only edit your own folders.** If two people never touch the same file, git can't conflict.
Ownership is in `AGENTS.md` section 2 and enforced by `.github/CODEOWNERS`.

## Setup (once)

- Repo: `github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08` (private, event org). Collaborators: `jrush-vj` (Jerush), `AbhiNav-S-Biju` (Abhinav), `AkchhatGrg` (Akchhat).
- Only Jerush pushes to `main`. Nobody force-pushes anything.
- One branch per person for the whole event: `feat/abhinav-p1-gateway`, `feat/akchhat-bank-dashboard`,
  `feat/jerush-analyst-core` (Jerush's integration branch).

## Daily loop (Abhinav, Akchhat)

```bash
git checkout feat/<your-branch>
git fetch origin && git merge origin/main     # start of every session: pick up the latest main
# ... work only inside your folders ...
git add <your-folder>/ team/<YOU>.md          # tick the step + add "READY TO MERGE (<date>): <what>"
git commit -m "honeypot: mirror transfer and search routes"
git push origin feat/<your-branch>               # Jerush sees the READY TO MERGE line and merges
```

- Use `git add <your-folder>/`, never `git add .` (it stops you committing someone else's files by accident).
- **Merge, never rebase, and never force-push.** Jerush merges your branch into his, so its history must not change.
- If a merge from `main` conflicts, you probably edited a file you don't own. Keep `main`'s version and ask the owner.

## Integration loop (Jerush)

```bash
git checkout feat/jerush-analyst-core
git fetch origin
git merge origin/feat/abhinav-p1-gateway      # order: shared/ → Abhinav → Akchhat → Jerush
git merge origin/feat/akchhat-bank-dashboard
docker compose down -v && docker compose up --build -d
docker compose run --rm <service> pytest -q   # gateway, analyst, mock-llm, ...
pytest tests/e2e -q
git push origin feat/jerush-analyst-core
git push origin feat/jerush-analyst-core:main # only if everything above is green
# then update the "▶ CURRENT" block in team/ABHINAV.md and team/AKCHHAT.md (their agents read it)
```

## When you need something outside your folders

| Need | Do |
|---|---|
| A new field in an event or rule | Write it under "Requests to Jerush" in your `team/<NAME>.md`, plus a message in the group chat |
| A new env var or compose change | Same as above |
| A new bank route, or a change to one (Abhinav) | Ask Akchhat |
| A change to the gateway's behaviour (Akchhat) | Ask Abhinav |

The owner makes the change on their branch. You get it after Jerush pushes it to `main` and you merge `origin/main`.

## Gates

A gate (see `docs/05-phases-and-gates.md`) is the same integration loop, plus a tag:

1. Everyone pushes their branch by the gate hour and tells Jerush.
2. Jerush runs the integration loop. If everything is green, he pushes to `main` and tags it.
3. Everyone runs `git fetch origin && git merge origin/main` before continuing.

## Never commit

`.env`, API keys, Cloudflare tokens, `*.db`, `node_modules/`, model files (`*.gguf`), `__pycache__/`.
The `.gitignore` (Jerush) covers these.
