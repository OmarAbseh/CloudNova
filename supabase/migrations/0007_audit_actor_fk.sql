-- =============================================================================
-- 0007_audit_actor_fk.sql, let the activity log name who acted
-- =============================================================================
-- Same shape as 0006, and caught before shipping this time. audit_log.actor
-- points at auth.users(id), and profiles.id points at auth.users(id), so
-- PostgREST has no edge to embed the actor's email through and answers:
--   "Could not find a relationship between 'audit_log' and 'profiles'"
--
-- An audit trail that cannot say who did something is not an audit trail, so
-- the foreign key is what makes the feature possible rather than a tidy-up.
--
-- ON DELETE SET NULL, not CASCADE: deleting a user must not delete the record
-- that they did something. The event survives with an unattributed actor,
-- which is the honest outcome, and it matches the existing auth.users
-- constraint on this column.
-- =============================================================================

do $$ begin
  alter table public.audit_log
    add constraint audit_log_actor_profiles_fkey
    foreign key (actor) references public.profiles (id) on delete set null;
exception when duplicate_object then null;
end $$;
