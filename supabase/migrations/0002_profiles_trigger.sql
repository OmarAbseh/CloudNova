-- =============================================================================
-- 0002_profiles_trigger.sql — provision a profile when a user signs up
-- =============================================================================
-- 0001 deliberately left this out: a trigger on `auth.users` needs rights on
-- the auth schema, so it belongs in its own migration that can fail loudly
-- rather than taking the whole platform schema down with it.
--
-- Until now the first authenticated request created the profile row from the
-- application (`tenancy.ensure_profile`). That works, but it is best-effort
-- and only runs if the user reaches a page. Doing it in the database means a
-- profile exists from the moment the account does, for every sign-up path —
-- including ones the dashboard never sees, like an invite accepted through
-- Supabase's own flows.
-- =============================================================================

-- SECURITY DEFINER because the trigger fires as the auth system, which has no
-- rights on public.profiles, and because the row must be written before the
-- user has any session for RLS to evaluate. Empty search_path so every
-- reference is explicit and no caller can shadow `profiles`.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    -- Supabase stashes whatever the sign-up form sent here; both keys are
    -- common in the wild and either is better than a null display name.
    nullif(
      coalesce(
        new.raw_user_meta_data ->> 'full_name',
        new.raw_user_meta_data ->> 'name',
        ''
      ),
      ''
    )
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

comment on function public.handle_new_user() is
  'Creates public.profiles row for a new auth.users row. Trigger-only.';

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Backfill anyone who signed up before this migration. Idempotent.
insert into public.profiles (id, email)
select u.id, u.email
from auth.users u
left join public.profiles p on p.id = u.id
where p.id is null;

-- Trigger functions have their EXECUTE checked when the trigger is created,
-- not when it fires, so revoking here keeps the trigger working while closing
-- the PostgREST RPC route that `create function` would otherwise open to
-- anon and authenticated.
revoke all on function public.handle_new_user() from public, anon, authenticated;
