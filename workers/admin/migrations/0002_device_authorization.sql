-- better-auth deviceAuthorization plugin table. Hand-authored to match the
-- plugin's schema in better-auth@1.6.11. Regenerate via @better-auth/cli
-- against migrations/better-auth.config.ts when bumping the plugin.

create table "deviceCode" (
  "id" text not null primary key,
  "deviceCode" text not null,
  "userCode" text not null,
  "userId" text references "user" ("id") on delete cascade,
  "expiresAt" date not null,
  "status" text not null,
  "lastPolledAt" date,
  "pollingInterval" integer,
  "clientId" text,
  "scope" text
);

create unique index "deviceCode_deviceCode_idx" on "deviceCode" ("deviceCode");
create unique index "deviceCode_userCode_idx" on "deviceCode" ("userCode");
create index "deviceCode_userId_idx" on "deviceCode" ("userId");
