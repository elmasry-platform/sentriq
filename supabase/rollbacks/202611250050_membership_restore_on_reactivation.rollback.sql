-- Rollback for 050: back to the 20261120 behaviour (every reactivation wipes grants).
drop function if exists api.membership_restore_report(uuid,uuid);
drop trigger if exists a_membership_suspension_snapshot on iam.memberships;
create or replace function private.reset_membership_authorizations_on_reactivation() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=coalesce(auth.uid(),new.user_id); v_reason text:='Reset on membership reactivation';
begin
 if old.status is distinct from 'active' and new.status='active' then
   update iam.membership_roles set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_id=new.id and revoked_at is null;
   update iam.membership_role_sites set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_role_id in
      (select id from iam.membership_roles where tenant_id=new.tenant_id and membership_id=new.id)
      and revoked_at is null;
   update iam.membership_role_org_units set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_role_id in
      (select id from iam.membership_roles where tenant_id=new.tenant_id and membership_id=new.id)
      and revoked_at is null;
   update iam.member_permissions set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.site_access set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.org_unit_access set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.task_assignments set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
 end if;
 return new;
end $$;
drop function if exists private.take_membership_suspension_snapshot();
drop function if exists private.restore_membership_access(uuid,uuid,uuid,uuid);
drop function if exists private.wipe_membership_authorizations(uuid,uuid,uuid);
drop function if exists private.membership_access_digest(uuid,uuid);
drop table if exists iam.membership_suspension_snapshots;
