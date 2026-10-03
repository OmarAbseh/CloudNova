-- =============================================================================
-- 0005_create_organization.sql, fix org creation
-- =============================================================================
-- Creating an organization through PostgREST was broken in production. Found by
-- the first live sign-in test, and invisible to the mocked tests because the
-- fake returned a row regardless of policy.
--
-- Why it failed: `insert` asks for the row back (Prefer: return=representation),
-- which makes it INSERT ... RETURNING. RETURNING is checked against the SELECT
-- policy, `is_member(id)`, and that is false at the moment it runs: the AFTER
-- INSERT trigger that makes the creator an owner has not fired yet, because
-- AFTER ROW triggers run at the end of the statement. So the row was created
-- and then rejected on the way out, surfacing as a 403 RLS violation.
--
-- Creating an org is really one atomic act, the org plus its founding
-- membership, so it belongs in a function rather than an insert plus a trigger
-- whose visibility rule depends on the trigger having already run. Same shape
-- and same reason as accept_invitation in 0003.
--
-- SECURITY DEFINER means the inserts here bypass RLS, so this function cannot
-- rely on the `created_by = auth.uid()` check in the INSERT policy. It sets
-- created_by from auth.uid() itself and ignores any caller-supplied value,
-- which makes forging the creator impossible rather than merely checked.
-- =============================================================================

create or replace function public.create_organization(org_name text)
returns public.organizations
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller uuid := (select auth.uid());
  created public.organizations;
begin
  if caller is null then
    raise exception 'Not signed in.' using errcode = '42501';
  end if;
  if coalesce(btrim(org_name), '') = '' then
    raise exception 'An organization name is required.' using errcode = '22023';
  end if;

  insert into public.organizations (name, created_by)
  values (btrim(org_name), caller)
  returning * into created;

  -- The trigger from 0001 has already inserted this; the conflict clause keeps
  -- both paths safe and makes the ownership explicit here rather than implied.
  insert into public.memberships (org_id, user_id, role)
  values (created.id, caller, 'owner')
  on conflict (org_id, user_id) do nothing;

  insert into public.audit_log (org_id, actor, action, detail)
  values (
    created.id, caller, 'organization.created',
    jsonb_build_object('name', created.name)
  );

  return created;
end;
$$;

comment on function public.create_organization(text) is
  'Creates an org with the caller as owner. Creator is always auth.uid().';

revoke all on function public.create_organization(text) from public, anon;
grant execute on function public.create_organization(text) to authenticated;
