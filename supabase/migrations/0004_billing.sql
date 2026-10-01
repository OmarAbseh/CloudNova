-- =============================================================================
-- 0004_billing.sql — plans, subscriptions and usage
-- =============================================================================
-- Billing hangs off the organization, not the user: a seat is a membership and
-- a scan belongs to an org, so the org is the only thing a limit can sensibly
-- apply to.
--
-- The important rule here is what is NOT granted. `subscriptions` has a read
-- policy and no write policy at all, so no signed-in user — not even an owner
-- — can insert or update their own row. If they could, upgrading to the top
-- plan would be a single PATCH. Stripe's webhook is the only writer, and it
-- authenticates with the service-role key, which bypasses RLS by design.
-- =============================================================================

-- A plan is a catalogue entry, not per-tenant data. Text ids so they read
-- plainly in queries and match the Stripe lookup keys.
create table if not exists public.plans (
  id                  text primary key,
  name                text not null,
  price_cents         integer not null default 0 check (price_cents >= 0),
  currency            text not null default 'eur',
  -- Null means unlimited. Zero would mean "none allowed", which is different.
  max_seats           integer check (max_seats is null or max_seats > 0),
  max_scans_per_month integer check (max_scans_per_month is null or max_scans_per_month >= 0),
  stripe_price_id     text,
  sort_order          integer not null default 0,
  is_active           boolean not null default true,
  created_at          timestamptz not null default now()
);

do $$ begin
  create type public.subscription_status as enum (
    'trialing', 'active', 'past_due', 'canceled', 'incomplete'
  );
exception when duplicate_object then null;
end $$;

-- One subscription per org. An org with no row is on the free plan — absence
-- is a valid state, so nothing has to backfill a row to make billing work.
create table if not exists public.subscriptions (
  org_id                 uuid primary key references public.organizations (id) on delete cascade,
  plan_id                text not null references public.plans (id),
  status                 public.subscription_status not null default 'active',
  stripe_customer_id     text,
  stripe_subscription_id text unique,
  current_period_end     timestamptz,
  cancel_at_period_end   boolean not null default false,
  created_at             timestamptz not null default now(),
  updated_at             timestamptz not null default now()
);

create index if not exists subscriptions_customer_idx
  on public.subscriptions (stripe_customer_id);

drop trigger if exists subscriptions_set_updated_at on public.subscriptions;
create trigger subscriptions_set_updated_at
  before update on public.subscriptions
  for each row execute function public.set_updated_at();

alter table public.plans enable row level security;
alter table public.subscriptions enable row level security;


-- -----------------------------------------------------------------------------
-- Policies
-- -----------------------------------------------------------------------------

-- The catalogue is public to anyone signed in — it is a price list, and the
-- pricing page needs it. Still no write policy: plans change by migration.
drop policy if exists "plans: readable by signed-in users" on public.plans;
create policy "plans: readable by signed-in users" on public.plans
  for select to authenticated
  using (is_active);

-- Members can see what their org is on. Nobody can change it. The absence of
-- an INSERT/UPDATE/DELETE policy here is the whole point: self-service
-- upgrades would otherwise be one request away.
drop policy if exists "subscriptions: members read" on public.subscriptions;
create policy "subscriptions: members read" on public.subscriptions
  for select to authenticated
  using (public.is_member(org_id));


-- -----------------------------------------------------------------------------
-- Usage
-- -----------------------------------------------------------------------------
-- SECURITY INVOKER on purpose, unlike the membership helpers. Those have to
-- bypass RLS to break a policy recursion; this one must not, because then it
-- would happily count another org's seats for any caller. Under invoker rights
-- a non-member simply gets zeros.

create or replace function public.org_usage(target_org uuid)
returns table (seats integer, pending_invites integer, scans_this_month integer)
language sql
stable
security invoker
set search_path = ''
as $$
  select
    (select count(*)::integer
       from public.memberships m
      where m.org_id = target_org),
    (select count(*)::integer
       from public.invitations i
      where i.org_id = target_org and i.status = 'pending'),
    (select count(*)::integer
       from public.scans s
      where s.org_id = target_org
        and s.started_at >= date_trunc('month', now() at time zone 'utc'));
$$;

comment on function public.org_usage(uuid) is
  'Seat and scan counts for an org. Invoker rights, so RLS scopes it to the caller.';


-- -----------------------------------------------------------------------------
-- Seed the catalogue
-- -----------------------------------------------------------------------------
-- Prices are placeholders until the Stripe products exist; stripe_price_id is
-- filled in from the dashboard. Seeding by merge so re-running is safe and an
-- edited row is not clobbered back to these defaults on every deploy.

insert into public.plans
  (id, name, price_cents, currency, max_seats, max_scans_per_month, sort_order)
values
  ('free',       'Free',        0,    'eur', 1,    20,   10),
  ('pro',        'Pro',         4900, 'eur', 10,   1000, 20),
  ('enterprise', 'Enterprise',  0,    'eur', null, null, 30)
on conflict (id) do nothing;


-- -----------------------------------------------------------------------------
-- Grants
-- -----------------------------------------------------------------------------
-- SELECT only. No write grant exists for either table, so even if a policy
-- were added by mistake the privilege would still be missing.

grant select on public.plans to authenticated;
grant select on public.subscriptions to authenticated;

revoke all on function public.org_usage(uuid) from public, anon;
grant execute on function public.org_usage(uuid) to authenticated;
