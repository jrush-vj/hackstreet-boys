# dashboard/ — owner: Akchhat

React + Vite + TypeScript + Tailwind, built with Node and served by nginx on port 3000.
nginx proxies `/api/*` and `/ws/*` to `analyst:8004` (keep the `resolver` + `set $analyst` lines in `nginx.conf`).
In dev, `npm run dev` (port 5173) proxies the same paths to `localhost:8004`.

- Types: `src/types.ts` mirrors `Event`, `Rule`, stats and timers from `docs/04-system-design.md`
- `src/App.tsx`: live feed (`/ws/live`, auto-reconnect), totals, OWASP 10-tile scoreboard, rules with on/off toggle, timers
- Checks: `npm test` (type check) and `npm run build`
- Tasks: `team/AKCHHAT.md`
