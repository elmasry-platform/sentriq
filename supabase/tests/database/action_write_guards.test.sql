-- Actions: write guards on hse.corrective_actions, hse.action_updates (append-only history) and hse.follow_ups.
-- Fixture: manager M, assigned employee E (assigned_task scope on one action), closure reviewer C, read-only outsider X in tenant A;
-- manager B in tenant B. Two A actions: one open and assigned to E, one waiting for closure review, plus one A action not assigned to E.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(30);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009d1','authenticated','authenticated','act-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009d2','authenticated','authenticated','act-m@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009d3','authenticated','authenticated','act-e@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009d4','authenticated','authenticated','act-c@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009d5','authenticated','authenticated','act-x@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009d6','authenticated','authenticated','act-b@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009d1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('9a000000-0000-0000-0000-00000000000a','Actions A','00000000-0000-0000-0000-0000000009d1'),('9b000000-0000-0000-0000-00000000000b','Actions B','00000000-0000-0000-0000-0000000009d1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('94000000-0000-0000-0000-000000000901','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009d2','employee','active','act-m@example.test'),
 ('94000000-0000-0000-0000-000000000902','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009d3','employee','active','act-e@example.test'),
 ('94000000-0000-0000-0000-000000000903','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009d4','employee','active','act-c@example.test'),
 ('94000000-0000-0000-0000-000000000904','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009d5','employee','active','act-x@example.test'),
 ('94000000-0000-0000-0000-000000000905','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009d6','employee','active','act-b@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) select x,'hse','active','00000000-0000-0000-0000-0000000009d1' from (values ('9a000000-0000-0000-0000-00000000000a'::uuid),('9b000000-0000-0000-0000-00000000000b'::uuid)) v(x);
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
 select e.tenant_id,e.module_key,e.created_at,'infinity'::timestamptz,e.changed_by,'Synthetic actions fixture','complimentary','legacy_backfill',e.id
 from core.tenant_entitlements e where e.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b') and e.module_key='hse';
insert into core.sites(id,tenant_id,name,code) values ('93000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','Act Site A','AA'),('93000000-0000-0000-0000-0000000000b1','9b000000-0000-0000-0000-00000000000b','Act Site B','AB');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
 ('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000901','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000902','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000903','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000904','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009d1'),
 ('9b000000-0000-0000-0000-00000000000b','94000000-0000-0000-0000-000000000905','93000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000009d1');
insert into iam.roles(tenant_id,role_key,label,role_family,created_by) values
 ('9a000000-0000-0000-0000-00000000000a','act_m','Act M','employee','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','act_e','Act E','employee','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','act_c','Act C','employee','00000000-0000-0000-0000-0000000009d1'),
 ('9a000000-0000-0000-0000-00000000000a','act_x','Act X','employee','00000000-0000-0000-0000-0000000009d1'),
 ('9b000000-0000-0000-0000-00000000000b','act_b','Act B','employee','00000000-0000-0000-0000-0000000009d1');
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
 select r.id,p.k,p.sc,true,p.w from iam.roles r join (values
 ('act_m','hse.actions.manage','tenant',true),
 ('act_m','hse.actions.read','tenant',false),
 ('act_e','hse.actions.update_assigned','assigned_task',true),
 ('act_e','hse.actions.read','assigned_task',false),
 ('act_c','hse.actions.close_review','tenant',true),
 ('act_c','hse.actions.read','tenant',false),
 ('act_x','hse.actions.read','tenant',false),
 ('act_b','hse.actions.manage','tenant',true),
 ('act_b','hse.actions.read','tenant',false)) p(rk,k,sc,w) on p.rk=r.role_key where r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by,published_at)
 select tenant_id,id,1,role_family,'published','00000000-0000-0000-0000-0000000009d1',now() from iam.roles where role_key like 'act\_%' and tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read,can_write)
 select rv.id,rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write from iam.role_versions rv join iam.role_permissions rp on rp.role_id=rv.role_id join iam.roles r on r.id=rv.role_id where r.role_key like 'act\_%' and r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
 select r.tenant_id,m.id,r.id,rv.id,'00000000-0000-0000-0000-0000000009d1' from iam.roles r join iam.role_versions rv on rv.role_id=r.id and rv.version_no=1
 join iam.memberships m on m.tenant_id=r.tenant_id and m.email='act-'||substr(r.role_key,5)||'@example.test'
 where r.role_key like 'act\_%';
set local session_replication_role = replica;
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values('94000000-0000-0000-0000-0000000009f1','9a000000-0000-0000-0000-00000000000a','{"en":"T"}','t','published',1,'{}','94000000-0000-0000-0000-000000000901','00000000-0000-0000-0000-0000000009d1');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by) values('95000000-0000-0000-0000-0000000009f1','9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-0000000009f1',1,'{}','00000000-0000-0000-0000-0000000009d1');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at) values('96000000-0000-0000-0000-0000000009f1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','94000000-0000-0000-0000-0000000009f1','95000000-0000-0000-0000-0000000009f1','Act insp','94000000-0000-0000-0000-000000000901','submitted','reviewer_1',now());
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by) values('97000000-0000-0000-0000-0000000009a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','96000000-0000-0000-0000-0000000009f1','Act finding','00000000-0000-0000-0000-0000000009d1');
insert into hse.corrective_actions(id,tenant_id,site_id,finding_id,inspection_id,title,owner_membership_id,created_by,status) values
 ('98000000-0000-0000-0000-0000000009a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','97000000-0000-0000-0000-0000000009a1','96000000-0000-0000-0000-0000000009f1','Open action','94000000-0000-0000-0000-000000000902','00000000-0000-0000-0000-0000000009d1','open'),
 ('98000000-0000-0000-0000-0000000009a2','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','97000000-0000-0000-0000-0000000009a1','96000000-0000-0000-0000-0000000009f1','Closure action','94000000-0000-0000-0000-000000000902','00000000-0000-0000-0000-0000000009d1','closure_requested'),
 ('98000000-0000-0000-0000-0000000009a3','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','97000000-0000-0000-0000-0000000009a1','96000000-0000-0000-0000-0000000009f1','Unassigned action','94000000-0000-0000-0000-000000000901','00000000-0000-0000-0000-0000000009d1','open');
insert into hse.follow_ups(id,tenant_id,action_id,title,owner_membership_id,due_at) values('99000000-0000-0000-0000-0000000009a1','9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-0000000009a1','Follow','94000000-0000-0000-0000-000000000902',now()+interval '3 days');
set local session_replication_role = origin;
insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by) values ('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000902','action','98000000-0000-0000-0000-0000000009a1','00000000-0000-0000-0000-0000000009d1'),('9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000902','action','98000000-0000-0000-0000-0000000009a2','00000000-0000-0000-0000-0000000009d1');
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d3',true);
select extensions.is((select count(*)::int from hse.corrective_actions where id='98000000-0000-0000-0000-0000000009a1' and true),1,'T01 positive control: assigned employee sees the assigned action');
select extensions.is((select count(*)::int from hse.corrective_actions where id='98000000-0000-0000-0000-0000000009a3' and true),0,'T02 assigned_task scope: the employee does not see an action not assigned to them');
select extensions.lives_ok($$update hse.corrective_actions set status='in_progress' where id='98000000-0000-0000-0000-0000000009a1'$$,'T03 assigned employee moves open -> in_progress');
select extensions.is((select count(*)::int from hse.action_updates where action_id='98000000-0000-0000-0000-0000000009a1' and status='in_progress'),1,'T04 the status change wrote one history row (trigger action_status_history)');
select extensions.throws_ok($$update hse.corrective_actions set status='closed' where id='98000000-0000-0000-0000-0000000009a1'$$,'42501','assigned action fields or transition are restricted','T05 assigned employee cannot close an action');
select extensions.throws_ok($$update hse.corrective_actions set title='Renamed' where id='98000000-0000-0000-0000-0000000009a1'$$,'42501','assigned action fields or transition are restricted','T06 assigned employee cannot edit other fields');
select extensions.lives_ok($$update hse.corrective_actions set status='closure_requested' where id='98000000-0000-0000-0000-0000000009a1'$$,'T07 assigned employee requests closure');
select extensions.throws_ok($$update hse.corrective_actions set status='closed' where id='98000000-0000-0000-0000-0000000009a2'$$,'42501','assigned action fields or transition are restricted','T08 assigned employee cannot approve closure');
select extensions.throws_ok($$insert into hse.action_updates(tenant_id,action_id,status) values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-0000000009a1','closed')$$,'42501',null,'T09 authenticated cannot write action history directly (no INSERT grant)');
select extensions.throws_ok($$update hse.action_updates set status='closed' where action_id='98000000-0000-0000-0000-0000000009a1'$$,'42501',null,'T10 authenticated cannot edit action history (no UPDATE grant)');
select extensions.lives_ok($$update hse.follow_ups set status='in_progress' where id='99000000-0000-0000-0000-0000000009a1'$$,'T11 assigned employee updates a follow-up on the assigned action');
select extensions.throws_ok($$insert into hse.follow_ups(tenant_id,action_id,title,owner_membership_id,due_at) values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-0000000009a3','Sneak','94000000-0000-0000-0000-000000000902',now()+interval '1 day')$$,'42501',null,'T12 assigned employee cannot add a follow-up to an action not assigned to them');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d4',true);
select extensions.throws_ok($$update hse.corrective_actions set title='Renamed by closer' where id='98000000-0000-0000-0000-0000000009a2'$$,'42501','insufficient_privilege','T13 closure reviewer cannot edit other fields (falls to the default deny)');
select extensions.lives_ok($$update hse.corrective_actions set status='closed' where id='98000000-0000-0000-0000-0000000009a2'$$,'T14 closure reviewer approves a requested closure');
select extensions.throws_ok($$update hse.corrective_actions set status='closed' where id='98000000-0000-0000-0000-0000000009a3'$$,'42501',null,'T15 closure reviewer cannot close an action that is not waiting for review');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d2',true);
select extensions.lives_ok($$update hse.corrective_actions set title='Renamed by manager' where id='98000000-0000-0000-0000-0000000009a3'$$,'T16 positive control: manager edits any field of an action');
select extensions.lives_ok($$update hse.follow_ups set title='Follow by manager' where id='99000000-0000-0000-0000-0000000009a1'$$,'T17 positive control: manager updates a follow-up');
select extensions.is((select title from hse.follow_ups where id='99000000-0000-0000-0000-0000000009a1'),'Follow by manager','T18 manager follow-up update took effect');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d5',true);
select extensions.is((select count(*)::int from hse.corrective_actions where id='98000000-0000-0000-0000-0000000009a2' and true),1,'T19 positive control: read-only user sees the action');
select extensions.lives_ok($$update hse.corrective_actions set title='Outsider edit' where id='98000000-0000-0000-0000-0000000009a3'$$,'T20 read-only user update runs but matches no row (RLS write policy hides it); verified unchanged at the end');
select extensions.lives_ok($$update hse.follow_ups set title='Outsider edit' where id='99000000-0000-0000-0000-0000000009a1'$$,'T21 read-only user follow-up update matches no row (RLS hides it); verified unchanged at the end');
select extensions.throws_ok($$insert into hse.follow_ups(tenant_id,action_id,title,owner_membership_id,due_at) values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-0000000009a3','Outsider','94000000-0000-0000-0000-000000000904',now()+interval '1 day')$$,'42501',null,'T22 read-only user cannot add follow-ups');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009d6',true);
select extensions.is((select count(*)::int from hse.corrective_actions where id='98000000-0000-0000-0000-0000000009a3' and true),0,'T23 tenant B manager cannot read A actions');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'T24 tenant B manager cannot read A action history');
select extensions.is((select count(*)::int from hse.follow_ups where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'T25 tenant B manager cannot read A follow-ups');
select extensions.throws_ok($$insert into hse.follow_ups(tenant_id,action_id,title,owner_membership_id,due_at) values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-0000000009a3','Cross','94000000-0000-0000-0000-000000000905',now()+interval '1 day')$$,'42501',null,'T26 tenant B manager cannot add a follow-up to a tenant A action');
select extensions.lives_ok($$update hse.corrective_actions set title='Hijack' where id='98000000-0000-0000-0000-0000000009a3'$$,'T27 tenant B manager update matches no A row (RLS hides it); verified unchanged at the end');
reset role;
select extensions.is((select status||'/'||title from hse.corrective_actions where id='98000000-0000-0000-0000-0000000009a3'),'open/Renamed by manager','T28 unassigned action keeps the manager edit after read-only and tenant B update attempts (no Outsider edit, no Hijack)');
select extensions.is((select title from hse.follow_ups where id='99000000-0000-0000-0000-0000000009a1'),'Follow by manager','T29 follow-up keeps the manager edit after read-only user attempt');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),3,'T30 exactly three history rows exist, one per permitted transition (in_progress, closure_requested, closed); denied attempts wrote none');
select * from extensions.finish();
rollback;
