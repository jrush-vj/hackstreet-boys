# bank/ — owner: Akchhat

VulnBank: a deliberately weak demo bank on port 8001, **internal network only**.
Also used as the `bank-sandbox` image (fresh DB per start).

- Routes and intentional weaknesses: `docs/04-system-design.md` section 8 (bank table)
- Mark each weakness in code with `# DEMO-WEAKNESS: A0x`
- `seed.py` builds fake data with Faker on first start
- Never expose this service through a tunnel or a public port
- Tasks: `team/AKCHHAT.md`
