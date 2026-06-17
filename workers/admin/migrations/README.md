# picket-admin D1 migrations

The `0001_better_auth.sql` migration must be generated from the better-auth CLI
so it stays in sync with the installed library version. The CLI can't introspect
the runtime D1 binding, so `better-auth.config.ts` in this directory stands in
as a CLI-only config with the same plugin set as the runtime auth.

Regenerate after upgrading `better-auth` or `@better-auth/api-key`:

```bash
cd workers/admin
pnpm exec better-auth generate \
  --config migrations/better-auth.config.ts \
  --output migrations/0001_better_auth.sql -y
```

Apply it to the remote D1:

```bash
pnpm exec wrangler d1 execute picket-auth --remote --file migrations/0001_better_auth.sql
```

Seed the synthetic system user that owns all MVP API keys:

```bash
node scripts/seed-system-user.mjs --remote
```

Set the better-auth signing secret:

```bash
pnpm exec wrangler secret put BETTER_AUTH_SECRET   # paste 32+ random bytes
```
