-- =============================================================================
-- 0003_invitations.sql — inviting people into an organization
-- =============================================================================
-- Two problems that 0001 deliberately left open, solved together because
-- neither is useful alone.
--
-- 1. An invitee is, by definition, not yet a member — so every policy in 0001
--    hides the org from them, and `memberships` only accepts writes from an
--    owner or admin. Acceptance therefore cannot be a plain INSERT by the
--    invitee; it needs a function that can see the invitation and act on it.
--
-- 2. A member list that cannot show who anyone is. 0001 made profiles
--    self-read-only, which is tight but means the people page would render
--    nothing but opaque user ids.
-- =============================================================================

do $$ begin
  create type public.invitation_status as enum ('pending', 'accepted', 'revoked');
exception when duplicate_object then null;
end $$;

create table if not exists public.invitations (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations (id) on delete cascade,
  -- Stored as typed; matched case-insensitively everywhere, since an email
  -- address differing only in case is the same person.
  email       text not null check (position('@' in email) > 1),
  role        public.org_role not null default 'member',
  status      public.invitation_status not null default 'pending',
  invited_by  uuid references auth.users (id) on delete set null,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default (now() + interval '14 days'),
  accepted_at timestamptz,
  accepted_by uuid references auth.users (id) on delete set null
);

-- At most one live invitation per address per org. Re-inviting someone who
-- already has one pending should be a no-op, not a second row to reconcile.
create unique index if not exists invitations_one_pending_per_email
  on public.invitations (org_id, lower(email))
  where status = 'pending';

create index if not exists invitations_email_idx on public.invitations (lower(email));
create index if not exists invitations_org_idx on public.invitations (org_id);

alter table public.invitations enable row level security;


-- -----------------------------------------------------------------------------
-- Seeing people you share an org with
-- -----------------------------------------------------------------------------

create or replace function public.shares_org(target_user uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships mine
    join public.memberships theirs on theirs.org_id = mine.org_id
    where mine.user_id = (select auth.uid())
      and theirs.user_id = target_user
  );
$$;

comment on function public.shares_org(uuid) is
  'True when the current user shares at least one org with the given user.';

-- Widens SELECT only. The self read/write policy from 0001 still stands, and
-- multiple permissive policies are OR-ed, so this adds co-member visibility
-- without granting anyone the ability to edit a profile but their own.
drop policy if exists "profiles: co-members read" on public.profiles;
create policy "profiles: co-members read" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or public.shares_org(id));


-- -----------------------------------------------------------------------------
-- Invitation policies
-- -----------------------------------------------------------------------------

-- Two ways to see an invitation: you administer the org, or it is addressed
-- to you. The second is what lets an invitee find it before they are a member
-- of anything.
drop policy if exists "invitations: members read" on public.invitations;
create policy "invitations: members read" on public.invitations
  for select to authenticated
  using (
    public.is_member(org_id)
    or lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );

drop policy if exists "invitations: admins create" on public.invitations;
create policy "invitations: admins create" on public.invitations
  for insert to authenticated
  with check (
    public.has_org_role(org_id, array['owner', 'admin']::public.org_role[])
    and invited_by = (select auth.uid())
  );

-- Revoking is an UPDATE to status. Acceptance does not go through here — it
-- runs in accept_invitation() below, which is the only way an invitee can
-- change a row in an org they cannot yet see.
drop policy if exists "invitations: admins update" on public.invitations;
create policy "invitations: admins update" on public.invitations
  for update to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

drop policy if exists "invitations: admins delete" on public.invitations;
create policy "invitations: admins delete" on public.invitations
  for delete to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));


-- -----------------------------------------------------------------------------
-- Accepting
-- -----------------------------------------------------------------------------
-- SECURITY DEFINER because the invitee has no rights in the target org yet.
-- That makes this the most powerful function in the schema, so every guard is
-- explicit: the caller must be signed in, the invitation must be pending and
-- unexpired, and its address must match the email in the caller's own verified
-- JWT. The membership it writes is always for auth.uid() — there is no
-- argument that lets a caller name a different user or a different role.

create or replace function public.accept_invitation(invitation_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  inv public.invitations;
  caller uuid := (select auth.uid());
  caller_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
begin
  if caller is null or caller_email = '' then
    raise exception 'Not signed in.' using errcode = '42501';
  end if;

  select * into inv
  from public.invitations
  where id = invitation_id
  for update;

  if not found then
    raise exception 'Invitation not found.' using errcode = 'P0002';
  end if;
  -- Same message for "belongs to someone else" as for "already used", so this
  -- cannot be used to probe which addresses have been invited where.
  if lower(inv.email) <> caller_email or inv.status <> 'pending' then
    raise exception 'Invitation not found.' using errcode = 'P0002';
  end if;
  if inv.expires_at < now() then
    raise exception 'This invitation has expired.' using errcode = 'P0002';
  end if;

  insert into public.memberships (org_id, user_id, role)
  values (inv.org_id, caller, inv.role)
  on conflict (org_id, user_id) do nothing;

  update public.invitations
     set status = 'accepted', accepted_at = now(), accepted_by = caller
   where id = inv.id;

  insert into public.audit_log (org_id, actor, action, detail)
  values (
    inv.org_id, caller, 'membership.accepted',
    jsonb_build_object('invitation_id', inv.id, 'role', inv.role)
  );

  return inv.org_id;
end;
$$;

comment on function public.accept_invitation(uuid) is
  'Redeems an invitation addressed to the caller. Only ever adds the caller.';


-- -----------------------------------------------------------------------------
-- Grants
-- -----------------------------------------------------------------------------

grant select, insert, update, delete on public.invitations to authenticated;

revoke all on function public.shares_org(uuid) from public, anon;
revoke all on function public.accept_invitation(uuid) from public, anon;
grant execute on function public.shares_org(uuid) to authenticated;
grant execute on function public.accept_invitation(uuid) to authenticated;
