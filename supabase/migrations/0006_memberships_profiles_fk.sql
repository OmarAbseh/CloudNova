-- =============================================================================
-- 0006_memberships_profiles_fk.sql, let the member list read profiles
-- =============================================================================
-- The organization settings page could not load. list_members embeds
-- profiles(email, full_name) from memberships, and PostgREST answered:
--   "Could not find a relationship between 'memberships' and 'profiles'"
--
-- PostgREST infers embedding from foreign keys. memberships.user_id points at
-- auth.users(id), and profiles.id points at auth.users(id), so the two tables
-- are siblings with no direct edge between them. 0003 made profiles readable
-- to co-members, which was necessary but not sufficient: the policy allowed
-- the read, and there was no relationship to read through.
--
-- Adding the foreign key states something already true, a membership always
-- belongs to someone who has a profile, since 0002 creates one for every new
-- auth.users row. It does introduce an ordering dependency: the profile must
-- exist before the membership. That is guaranteed by the trigger, and
-- tenancy.ensure_profile remains as a safety net for a database that predates
-- 0002.
--
-- The existing auth.users foreign key stays. Two constraints on one column is
-- mild redundancy, and each states a real thing.
-- =============================================================================

-- Backfill first, so adding the constraint cannot fail on existing rows.
insert into public.profiles (id, email)
select u.id, u.email
from auth.users u
left join public.profiles p on p.id = u.id
where p.id is null
  and exists (select 1 from public.memberships m where m.user_id = u.id);

do $$ begin
  alter table public.memberships
    add constraint memberships_user_id_profiles_fkey
    foreign key (user_id) references public.profiles (id) on delete cascade;
exception when duplicate_object then null;
end $$;
