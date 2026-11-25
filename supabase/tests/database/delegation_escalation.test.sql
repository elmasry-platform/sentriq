-- Delegation escalation edges: a delegate cannot grant beyond its own envelope, limits and window; revoke cascades.
-- Users: 2 superadmin (tenant A), 3 delegate admin, 4 employee, 5 employee with no envelope, 6 superadmin (tenant B), 7 employee (B),
-- 8 admin with a time-boxed envelope, 9 admin with an employees_default envelope.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(31);
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('70000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','deleg-esc-'||i||'@example.test',now(),now(),now() from generate_series(1,10) i;
select private.bootstrap_platform_owner('70000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values ('71000000-0000-0000-0000-000000000001','Deleg A','70000000-0000-0000-0000-000000000001'),('71000000-0000-0000-0000-000000000002','Deleg B','70000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email) values
 ('72000000-0000-0000-0000-000000000002','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000002','company_superadmin','deleg-esc-2@example.test'),
 ('72000000-0000-0000-0000-000000000003','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000003','company_admin','deleg-esc-3@example.test'),
 ('72000000-0000-0000-0000-000000000004','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000004','employee','deleg-esc-4@example.test'),
 ('72000000-0000-0000-0000-000000000005','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000005','employee','deleg-esc-5@example.test'),
 ('72000000-0000-0000-0000-000000000006','71000000-0000-0000-0000-000000000002','70000000-0000-0000-0000-000000000006','company_superadmin','deleg-esc-6@example.test'),
 ('72000000-0000-0000-0000-000000000007','71000000-0000-0000-0000-000000000002','70000000-0000-0000-0000-000000000007','employee','deleg-esc-7@example.test'),
 ('72000000-0000-0000-0000-000000000008','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000008','company_admin','deleg-esc-8@example.test'),
 ('72000000-0000-0000-0000-000000000009','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000009','company_admin','deleg-esc-9@example.test'),
 ('72000000-0000-0000-0000-000000000010','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000010','employee','deleg-esc-10@example.test');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select t,'hse',now()-interval '1 day',now()+interval '1 day','70000000-0000-0000-0000-000000000001','Deleg fixture entitlement','complimentary' from unnest(array['71000000-0000-0000-0000-000000000001'::uuid,'71000000-0000-0000-0000-000000000002'::uuid]) t;
create temporary table env(k text primary key, id uuid not null) on commit drop;
grant insert,select on table pg_temp.env to authenticated;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason)
 values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','view_all','allow','tenant',true,'70000000-0000-0000-0000-000000000002','Delegate holds view_all so it can pass it on within its envelope');
select set_config('sentriq.migration_runner','off',true);
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
insert into env select 'P',(select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',null,null,array['role_assignment','direct_permission_decision'],now(),null,'Parent envelope'));
insert into env select 'X',(select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000008','tenant',null,null,array['role_assignment'],now(),now()+interval '1 hour','Time boxed envelope'));
insert into env select 'Y',(select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000009','employees_default',null,null,array['role_assignment'],now(),null,'Employees default envelope'));
insert into env select 'Z',(select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000009','employees_default',null,null,array['scope_management'],now(),null,'Second envelope with another capability'));
select extensions.is((select count(*)::int from env),4,'D01 positive control: the superadmin created four parent envelopes (user 9 holds two employees_default envelopes with different capabilities)');
select extensions.is((select count(*)::int from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation.created'),4,'D02 each creation wrote an audit event');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
insert into env select 'C',(select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'Child inside parent'));
select extensions.is((select parent_envelope_id=(select id from env where k='P') from iam.delegation_envelopes where id=(select id from env where k='C')),true,'D03 positive control: the delegate child envelope is linked to its parent');
insert into env select 'DEC',(select api.set_member_permission_decision('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','view_all','allow','tenant',null,null,null,null,true,false,null,null,'Decision made by the delegate'));
reset role;
select extensions.is((select x.source_delegation_id=(select id from env where k='P') from iam.member_permission_decisions x where x.id=(select id from env where k='DEC')),true,'D04 positive control: the delegate decision is sourced from the parent envelope');
set local role authenticated;
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['scope_management'],now(),null,'Beyond parent capabilities')$$,'42501','delegation_capability_not_authorized','D05 a delegate cannot grant a capability it does not hold');
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment','scope_management'],now(),null,'One capability too many')$$,'42501','delegation_capability_not_authorized','D06 one capability beyond the envelope is enough to refuse the whole request');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000008',true);
select extensions.lives_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),now()+interval '30 minutes','Inside the window')$$,'D07 positive control: a child that ends before its time-boxed parent is allowed');
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','tenant',null,null,array['role_assignment'],now(),null,'Open ended child')$$,'42501','delegation_parent_envelope_required','D08 a child with no end cannot hang off a time-boxed parent');
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','tenant',null,null,array['role_assignment'],now(),now()+interval '3 hours','Child outlives parent')$$,'42501','delegation_parent_envelope_required','D09 a child cannot outlive its parent envelope');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000009',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','tenant',null,null,array['role_assignment'],now(),null,'Level escalation')$$,'42501','delegation_parent_envelope_required','D10 an employees_default delegate cannot grant at tenant level');
select extensions.lives_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','employees_default',null,null,array['role_assignment'],now(),null,'Same level')$$,'D11 positive control: the same level is allowed');
select extensions.lives_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','employees_default',null,null,array['scope_management'],now(),null,'Second envelope, other capability')$$,'D12 positive control: each capability is allowed on its own through the envelope that holds it');
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','employees_default',null,null,array['role_assignment','scope_management'],now(),null,'Two capabilities from two envelopes')$$,'42501','delegation_parent_envelope_required','D13 capabilities held through two different envelopes cannot be combined into one child (no single parent covers both; only the parent subset check stops this)');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000004',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000005',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'Widen from a child envelope')$$,'42501','delegation_parent_envelope_required','D14 a delegate of an employees_default child cannot widen to tenant level');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000010',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'No envelope at all')$$,'42501','delegation_capability_not_authorized','D15 an employee with no envelope cannot delegate');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000006',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'Cross company')$$,'22023','delegation_request_invalid','D16 a superadmin of company B cannot delegate inside company A');
reset role;
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason) values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','scope_management',true,false,'70000000-0000-0000-0000-000000000001','Fixture: use but not delegate');
set local role authenticated;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',null,null,array['scope_management'],now(),null,'Non delegable capability')$$,'42501','delegation_capability_not_authorized','D17 a superadmin cannot delegate a capability limited to use-only');
select extensions.lives_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',null,null,array['direct_permission_decision'],now(),null,'Another capability stays delegable')$$,'D18 positive control: the limit is per capability, others stay delegable');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000005',true);
select extensions.throws_ok($$select api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from env where k='P'),'Not mine to revoke')$$,'42501','delegation_revoke_not_authorized','D19 an employee cannot revoke another user envelope');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
select extensions.throws_ok($$select api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from env where k='P'),'Delegate revokes own parent')$$,'42501','delegation_revoke_not_authorized','D20 a delegate cannot revoke the envelope that was granted to it');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
select extensions.throws_ok($$select api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from env where k='P'),'x')$$,'22023','delegation_revoke_invalid','D21 a too-short reason is refused');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000004',true);
select extensions.is((select private.phase1_permission_allowed('71000000-0000-0000-0000-000000000001','view_all',null,null,false,null,null)),true,'D22 positive control: before the revoke the employee holds view_all through the delegated decision');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.is((select api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from env where k='P'),'Superadmin withdraws parent')),2,'D23 revoking the parent returns 2: the parent and the child under it');
reset role;
select extensions.is((select string_agg(status,',' order by k) from (select e.k,d.status from env e join iam.delegation_envelopes d on d.id=e.id where e.k in ('P','C')) s),'revoked,revoked','D24 both the parent and the child are revoked');
select extensions.is((select count(*)::int from iam.delegation_review_events where envelope_id=(select id from env where k='P') and action='revoke'),1,'D25 one revoke review event was written for the parent');
select extensions.is((select count(*)::int from iam.delegation_envelopes where status='active' and tenant_id='71000000-0000-0000-0000-000000000001' and parent_envelope_id=(select id from env where k='P')),0,'D26 no active child is left under the revoked parent');
select extensions.is((select (select count(*)::int from iam.delegation_envelopes where id=(select id from env where k='X') and status='active')),1,'D27 unrelated envelope X is still active');
select extensions.is((select private.decision_source_valid((select source_delegation_id from iam.member_permission_decisions where id=(select id from env where k='DEC')),'71000000-0000-0000-0000-000000000001')),false,'D28 the delegated decision no longer has a valid source after the revoke');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000004',true);
select extensions.is((select private.phase1_permission_allowed('71000000-0000-0000-0000-000000000001','view_all',null,null,false,null,null)),false,'D29 the employee loses view_all once the envelope is revoked (effective permission, not just status)');
reset role;
select extensions.is((select status||'/'||suspended_by_tenant::text from iam.member_permission_decisions where id=(select id from env where k='DEC')),'suspended/false','D30 the derived decision row is marked suspended by the revoke (independent of the read-time source check)');
set local role authenticated;
set local role authenticated;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
select extensions.throws_ok($$select api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'After revoke')$$,'42501','delegation_capability_not_authorized','D31 after the revoke the delegate cannot create new envelopes');
reset role;
select * from extensions.finish();
rollback;
