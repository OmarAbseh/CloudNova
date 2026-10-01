-- =============================================================================
-- 0001_platform.sql — Floatly Platform + CloudNova multi-tenant schema
-- =============================================================================
-- Two layers, one migration:
--
--   1. Floatly Platform (shared across Floatly products): organizations,
--      profiles, memberships, audit_log. Shared *code/schema shape*, not a
--      shared database — each product deploys this into its own project.
--   2. CloudNova per-org data: targets, scans, findings.
--
-- Tenant isolation is enforced by Row-Level Security, not by application code.
-- The rule everywhere is the same: a row is visible only if the caller is a
-- member of the org that owns it. Writes additionally require a sufficient
-- role. Nothing is ever granted to `anon`.
--
-- Re-runnable: enum creation, policies and triggers are all guarded, so
-- applying this twice is a no-op rather than an error.
--
-- Deliberately NOT in this migration (next steps, not oversights):
--   * auto-provisioning `profiles` from an `auth.users` trigger — needs owner
--     rights on the auth schema; do it as its own migration.
--   * co-member profile visibility (today a profile is self-read only, per the
--     platform baseline) — a members list UI will need a shared-org policy.
--   * guarding admin -> owner self-escalation on `memberships` beyond the
--     owner-only UPDATE policy below.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------
-- `create type` has no `if not exists`, so each is wrapped to stay re-runnable.

do $$ begin
  create type public.org_role as enum ('owner', 'admin', 'member', 'viewer');
exception when duplicate_object then null;
end $$;

-- Mirrors the CLI surface: `cloudnova scan <path>` (iac) and
-- `cloudnova cloud aws|azure|gcp`.
do $$ begin
  create type public.target_kind as enum ('iac', 'aws', 'azure', 'gcp');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type public.scan_status as enum ('pending', 'running', 'succeeded', 'failed');
exception when duplicate_object then null;
end $$;

-- Values match cloudnova.core.findings.Severity / .Confidence exactly, so a
-- Pydantic model dumps straight into these columns with no translation layer.
do $$ begin
  create type public.finding_severity as enum ('critical', 'high', 'medium', 'low', 'info');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type public.finding_confidence as enum ('high', 'medium', 'low');
exception when duplicate_object then null;
end $$;


-- =============================================================================
-- Layer 1 — Floatly Platform
-- =============================================================================

-- Organizations (tenants).
create table if not exists public.organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (length(btrim(name)) > 0),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Profiles: 1:1 with auth.users.
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  email      text,
  full_name  text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Membership: which user belongs to which org, with a role.
create table if not exists public.memberships (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  role       public.org_role not null default 'member',
  created_at timestamptz not null default now(),
  unique (org_id, user_id)
);

create index if not exists memberships_user_id_idx on public.memberships (user_id);
create index if not exists memberships_org_id_idx  on public.memberships (org_id);

-- Audit log. Append-only by construction: members may INSERT and SELECT, and
-- there is no UPDATE or DELETE policy or grant, so neither is reachable.
create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  org_id     uuid references public.organizations (id) on delete cascade,
  actor      uuid references auth.users (id) on delete set null,
  action     text not null,
  detail     jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create index if not exists audit_log_org_created_idx
  on public.audit_log (org_id, created_at desc);


-- =============================================================================
-- Helper functions
-- =============================================================================
-- These are SECURITY DEFINER on purpose. A policy on `memberships` that itself
-- queries `memberships` would recurse infinitely; running the lookup as the
-- function owner sidesteps RLS on that inner read and breaks the cycle.
--
-- `search_path = ''` means no schema is implicit, so every reference below is
-- fully qualified. That is what stops a caller from shadowing `memberships`
-- with their own table and steering the check.

create or replace function public.is_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.org_id = target_org
      and m.user_id = (select auth.uid())
  );
$$;

comment on function public.is_member(uuid) is
  'True when the current user belongs to the given org. Basis of every read policy.';

create or replace function public.has_org_role(
  target_org uuid,
  allowed public.org_role[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.org_id = target_org
      and m.user_id = (select auth.uid())
      and m.role = any(allowed)
  );
$$;

comment on function public.has_org_role(uuid, public.org_role[]) is
  'True when the current user holds one of the given roles in the org. Basis of every write policy.';

-- Creating an org would otherwise be a dead end: RLS hides any org you are not
-- already a member of, and only owners/admins can add memberships. This makes
-- the creator the first owner so the tenant is reachable.
create or replace function public.handle_new_organization()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is not null then
    insert into public.memberships (org_id, user_id, role)
    values (new.id, auth.uid(), 'owner'::public.org_role)
    on conflict (org_id, user_id) do nothing;
  end if;
  return new;
end;
$$;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists organizations_grant_creator_owner on public.organizations;
create trigger organizations_grant_creator_owner
  after insert on public.organizations
  for each row execute function public.handle_new_organization();

drop trigger if exists organizations_set_updated_at on public.organizations;
create trigger organizations_set_updated_at
  before update on public.organizations
  for each row execute function public.set_updated_at();

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();


-- =============================================================================
-- Layer 2 — CloudNova per-org data
-- =============================================================================
-- Every table carries its own `org_id` rather than reaching the tenant through
-- a join. RLS runs on each row of each table, so a join would mean re-walking
-- the chain on every check. The denormalisation is kept honest by composite
-- foreign keys: a scan can only point at a target in the same org, and a
-- finding only at a scan in the same org. Drift is impossible, not merely
-- discouraged.

-- What gets scanned: an IaC path/repo, or a live cloud account.
create table if not exists public.targets (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations (id) on delete cascade,
  name        text not null check (length(btrim(name)) > 0),
  kind        public.target_kind not null,
  -- Filesystem path, repo URL, AWS account id, Azure subscription, GCP project.
  identifier  text,
  created_by  uuid references auth.users (id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (org_id, id)
);

create index if not exists targets_org_id_idx on public.targets (org_id);

-- One scan run. The summary columns mirror the `summary` block of
-- `cloudnova.reporting.json_report.render_json`.
create table if not exists public.scans (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references public.organizations (id) on delete cascade,
  target_id       uuid not null,
  status          public.scan_status not null default 'pending',
  started_at      timestamptz not null default now(),
  finished_at     timestamptz,
  files_scanned   integer not null default 0 check (files_scanned >= 0),
  checks_run      integer not null default 0 check (checks_run >= 0),
  findings_count  integer not null default 0 check (findings_count >= 0),
  -- 0-100, higher = worse (see cloudnova.scoring.posture_score).
  posture_score   integer check (posture_score between 0 and 100),
  grade           text check (grade in ('A', 'B', 'C', 'D', 'F')),
  score_breakdown jsonb not null default '{}',
  errors          jsonb not null default '[]',
  created_by      uuid references auth.users (id) on delete set null,
  created_at      timestamptz not null default now(),
  unique (org_id, id),
  foreign key (target_id, org_id)
    references public.targets (id, org_id) on delete cascade
);

create index if not exists scans_org_id_idx on public.scans (org_id);
create index if not exists scans_target_started_idx
  on public.scans (target_id, started_at desc);

-- One finding. Columns map 1:1 onto cloudnova.core.findings.Finding; the
-- nested `location` is flattened so it can be indexed and filtered, and
-- `references` is stored as `reference_urls` because the original name is a
-- reserved word in SQL and would need quoting in every query.
create table if not exists public.findings (
  id                uuid primary key default gen_random_uuid(),
  org_id            uuid not null references public.organizations (id) on delete cascade,
  scan_id           uuid not null,
  check_id          text not null,
  title             text not null,
  severity          public.finding_severity not null,
  confidence        public.finding_confidence not null default 'high',
  location_path     text not null,
  location_line     integer,
  location_resource text,
  description       text not null,
  remediation       text not null,
  evidence          text,
  reference_urls    text[] not null default '{}',
  cis_controls      text[] not null default '{}',
  mitre_attack      text[] not null default '{}',
  detected_at       timestamptz not null default now(),
  created_at        timestamptz not null default now(),
  foreign key (scan_id, org_id)
    references public.scans (id, org_id) on delete cascade
);

create index if not exists findings_org_id_idx      on public.findings (org_id);
create index if not exists findings_scan_id_idx     on public.findings (scan_id);
create index if not exists findings_org_sev_idx     on public.findings (org_id, severity);
create index if not exists findings_check_id_idx    on public.findings (check_id);

drop trigger if exists targets_set_updated_at on public.targets;
create trigger targets_set_updated_at
  before update on public.targets
  for each row execute function public.set_updated_at();


-- =============================================================================
-- Row-Level Security
-- =============================================================================

alter table public.organizations enable row level security;
alter table public.profiles      enable row level security;
alter table public.memberships   enable row level security;
alter table public.audit_log     enable row level security;
alter table public.targets       enable row level security;
alter table public.scans         enable row level security;
alter table public.findings      enable row level security;

-- RLS denies by default, so anything without a policy below is unreachable for
-- `authenticated` no matter what grants exist. Policies are dropped first to
-- keep the migration re-runnable.

-- --- organizations -----------------------------------------------------------
drop policy if exists "orgs: members read" on public.organizations;
create policy "orgs: members read" on public.organizations
  for select to authenticated
  using (public.is_member(id));

-- Anyone signed in may create an org; the trigger above makes them its owner.
drop policy if exists "orgs: authenticated create" on public.organizations;
create policy "orgs: authenticated create" on public.organizations
  for insert to authenticated
  with check (created_by = (select auth.uid()));

drop policy if exists "orgs: admins update" on public.organizations;
create policy "orgs: admins update" on public.organizations
  for update to authenticated
  using (public.has_org_role(id, array['owner', 'admin']::public.org_role[]))
  with check (public.has_org_role(id, array['owner', 'admin']::public.org_role[]));

drop policy if exists "orgs: owners delete" on public.organizations;
create policy "orgs: owners delete" on public.organizations
  for delete to authenticated
  using (public.has_org_role(id, array['owner']::public.org_role[]));

-- --- profiles ----------------------------------------------------------------
-- Self only, per the platform baseline. Co-member visibility is a follow-up.
drop policy if exists "profiles: self read/write" on public.profiles;
create policy "profiles: self read/write" on public.profiles
  for all to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- --- memberships -------------------------------------------------------------
drop policy if exists "memberships: members read" on public.memberships;
create policy "memberships: members read" on public.memberships
  for select to authenticated
  using (public.is_member(org_id));

drop policy if exists "memberships: admins invite" on public.memberships;
create policy "memberships: admins invite" on public.memberships
  for insert to authenticated
  with check (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

-- Owner-only, because an UPDATE here is a role change.
drop policy if exists "memberships: owners change role" on public.memberships;
create policy "memberships: owners change role" on public.memberships
  for update to authenticated
  using (public.has_org_role(org_id, array['owner']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner']::public.org_role[]));

drop policy if exists "memberships: admins remove" on public.memberships;
create policy "memberships: admins remove" on public.memberships
  for delete to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

-- --- audit_log ---------------------------------------------------------------
drop policy if exists "audit: members read" on public.audit_log;
create policy "audit: members read" on public.audit_log
  for select to authenticated
  using (public.is_member(org_id));

-- Members may append, and only as themselves — no back-dating another actor.
-- No UPDATE/DELETE policy exists, which is what makes the log append-only.
drop policy if exists "audit: members append" on public.audit_log;
create policy "audit: members append" on public.audit_log
  for insert to authenticated
  with check (public.is_member(org_id) and actor = (select auth.uid()));

-- --- targets / scans / findings ----------------------------------------------
-- Same shape on all three: members read, non-viewers write, admins delete.
-- `viewer` is read-only by omission from the write role arrays.

drop policy if exists "targets: members read" on public.targets;
create policy "targets: members read" on public.targets
  for select to authenticated
  using (public.is_member(org_id));

drop policy if exists "targets: members write" on public.targets;
create policy "targets: members write" on public.targets
  for insert to authenticated
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "targets: members update" on public.targets;
create policy "targets: members update" on public.targets
  for update to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "targets: admins delete" on public.targets;
create policy "targets: admins delete" on public.targets
  for delete to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

drop policy if exists "scans: members read" on public.scans;
create policy "scans: members read" on public.scans
  for select to authenticated
  using (public.is_member(org_id));

drop policy if exists "scans: members write" on public.scans;
create policy "scans: members write" on public.scans
  for insert to authenticated
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "scans: members update" on public.scans;
create policy "scans: members update" on public.scans
  for update to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "scans: admins delete" on public.scans;
create policy "scans: admins delete" on public.scans
  for delete to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

drop policy if exists "findings: members read" on public.findings;
create policy "findings: members read" on public.findings
  for select to authenticated
  using (public.is_member(org_id));

drop policy if exists "findings: members write" on public.findings;
create policy "findings: members write" on public.findings
  for insert to authenticated
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "findings: members update" on public.findings;
create policy "findings: members update" on public.findings
  for update to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner', 'admin', 'member']::public.org_role[]));

drop policy if exists "findings: admins delete" on public.findings;
create policy "findings: admins delete" on public.findings
  for delete to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));


-- =============================================================================
-- Grants
-- =============================================================================
-- The project has "auto-expose new tables" OFF, so table privileges have to be
-- granted here explicitly. `anon` is granted nothing at all: unauthenticated
-- callers get no reach into any of these tables, and RLS above narrows what a
-- signed-in caller can see within the privileges below.

grant usage on schema public to authenticated;

grant select, insert, update, delete on public.organizations to authenticated;
grant select, insert, update, delete on public.profiles      to authenticated;
grant select, insert, update, delete on public.memberships   to authenticated;
grant select, insert, update, delete on public.targets       to authenticated;
grant select, insert, update, delete on public.scans         to authenticated;
grant select, insert, update, delete on public.findings      to authenticated;

-- Append-only: no update/delete privilege is granted at all.
grant select, insert on public.audit_log to authenticated;

-- Function privileges.
--
-- `create function` grants EXECUTE to PUBLIC by default, and `anon` inherits
-- that — which would publish every function below as a callable PostgREST RPC
-- endpoint. Revoke first, then hand back only what is actually needed.
revoke all on function public.is_member(uuid) from public, anon;
revoke all on function public.has_org_role(uuid, public.org_role[]) from public, anon;
revoke all on function public.handle_new_organization() from public, anon, authenticated;
revoke all on function public.set_updated_at() from public, anon, authenticated;

-- The two helpers do need to stay executable by `authenticated`: a policy
-- expression is evaluated as the querying role, so without EXECUTE here every
-- policy above would fail for real users. They leak nothing — for a caller
-- with no session `auth.uid()` is null and both return false.
grant execute on function public.is_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid, public.org_role[]) to authenticated;

-- `handle_new_organization` and `set_updated_at` need no grant at all: trigger
-- EXECUTE privileges are checked when the trigger is created, not when it
-- fires, so revoking here leaves the triggers working and closes the RPC route.
