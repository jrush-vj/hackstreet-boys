# dashboard/ — owner: Akchhat

React + Vite + TypeScript + Tailwind, served by nginx on port 3000.
nginx proxies `/api/*` and `/ws/*` to `analyst:8004`. In dev, `npm run dev` (port 5173) proxies the same paths to `localhost:8004`.

- Types: `src/types.ts` mirrors `Event`, `Rule` and stats from `docs/04-system-design.md`
- Pages/panels: live feed, OWASP 10-tile scoreboard, rules, timer, Run scenario
- Tasks: `team/AKCHHAT.md`
