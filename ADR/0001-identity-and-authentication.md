# ADR 0001: Identity and Authentication

| Field | Value |
|---|---|
| Status | PROPOSED — AWAITING OWNER APPROVAL |
| Decision date | 2026-11-20 |
| Scope | HSE release and future Laravel backend; no identity implementation is changed by this ADR. |

## Context

The current schema references `auth.users(id)` from tenant memberships, operator records, creators, reviewers, invitation records, audit fields, and other business rows. Policies and privileged functions use `auth.uid()`, `auth.role()`, and Supabase JWT request claims. The local Supabase project is configured for PostgreSQL 15 and exposes `api`, `core`, `iam`, `hse`, and `audit` through PostgREST while keeping `private` unexposed. Supabase Auth is therefore the current identity provider in the actual migration design, even though Laravel does not exist yet.

The implementation does not include the deployed Auth configuration, Laravel middleware, session code, MFA requirements, SSO provider, or recovery procedures. The database schema alone cannot prove those controls. The invitation functions also accept user/actor UUIDs from a service-role caller; that caller must bind them to verified Auth identity.

## Options

| Criterion | Option A — Supabase Auth; Laravel validates Supabase JWT | Option B — Laravel-managed identity; migrate to internal IAM identity |
|---|---|---|
| Security | Keeps the currently designed signed Auth identity and database RLS context. Laravel must validate issuer, audience, signature, expiry, and required claims. Service credentials stay server-only. | Gives Laravel direct control of login/session policy, but requires a new trusted database actor context. A client-controlled GUC is forgeable; only trusted middleware may set transaction-local claims from an authenticated session. |
| Operations | Supabase operates identity, confirmation, recovery, token refresh, and Auth availability. Laravel still needs secure session/token storage and error handling. | SENTRIQ owns password storage or an identity provider integration, credential abuse defenses, recovery, session revocation, MFA enrollment/recovery, and operational monitoring. |
| Migration effort | Smallest path. `auth.users` foreign keys and `auth.uid()`/`auth.role()` remain compatible. | Large migration. Replace identity FKs, claims, policies, actor derivation, invitation acceptance, tests, and bootstrap workflow; plan identity-ID mapping and a coordinated cutover. |
| Migration compatibility | Direct fit for all four current migrations and current tests. | Requires forward migrations or a deliberate schema redesign before implementation; changing only Laravel auth would not make these database policies portable. |
| Multi-tenant isolation | RLS can continue to use the verified Auth subject with tenant membership rows. | RLS still works only if Laravel establishes an unforgeable-from-client transaction context. The internal identity model must own status and tenant bindings. |
| Invitations | Existing RPC checks token hash, one-use row lock, expiry/revocation, and verified matching `auth.users.email`. F-01 must be closed to make that the only activation path. | Laravel can own invitation email and token flow but must preserve hash storage, one-use semantics, mailbox proof, atomic acceptance, and the active-user FK transaction. |
| MFA and platform operators | Supabase Auth supports MFA; configuration and app policy must require step-up for platform operator actions. Current SQL does not check an AAL claim. | Laravel can select an MFA/session provider, but SENTRIQ owns enrollment, recovery, step-up, enforcement, and high-assurance operator account recovery. |
| Future Operations module | Shared identity lets HSE and Operations reuse one membership and Auth subject. | Shared internal IAM can be module-agnostic, but all future modules must migrate to and consistently use the new identity. |
| Vendor dependency | Supabase Auth remains an identity vendor dependency; Auth user IDs and JWT semantics are embedded in the schema. | Reduces Supabase Auth dependency if SENTRIQ owns identity, but still depends on PostgreSQL/Supabase for the database and storage unless those are also migrated. |
| Long-term maintenance | Lower near-term change surface. Keep an adapter boundary in Laravel so business code does not depend on SDK specifics. | More control and more lifecycle/security code to maintain. A managed external IdP can reduce some burden, but still needs mapping, token validation, and database context design. |

## Proposed decision

Choose **Option A for the initial HSE release**. Keep Supabase Auth as the identity source and preserve `auth.users` references, JWT subject, and database RLS. Have Laravel validate Supabase access tokens with a supported verification path, establish its own server-side session if desired, and derive the actor from validated claims. For user-scoped database access, preserve that verified identity through PostgREST or use a carefully constrained direct-DB transaction. Do not use the `service_role` credential for normal user requests.

This choice matches current migrations and avoids an identity migration before HSE is running. It does not commit SENTRIQ to using Supabase Auth forever: isolate identity validation behind Laravel interfaces and revisit Option B when enterprise SSO, data residency, identity-provider portability, or operational cost requires it. Any later switch needs a dedicated migration and cutover plan.

## Required safeguards before production

- Require verified email for invitation acceptance; close F-01 so table writes cannot bypass that flow.
- Require MFA/step-up for Owner and Subowner accounts and for high-impact platform functions. Test denial for a token without the required AAL.
- Keep access and refresh tokens out of logs. Store refresh tokens in a protected server-side session or use a deliberately reviewed client flow.
- Define access-token lifetime, refresh rotation, inactivity/absolute session limits, global sign-out, account suspension, Auth-user deletion, lost-factor recovery, and operator break-glass procedure.
- Treat local service keys as test-only; rotate and protect all hosted secrets. The Supabase service-role key bypasses RLS.
- Laravel must derive actor UUIDs from its validated session/token. Reject caller-supplied actor UUIDs for `api.create_invitation`, `api.accept_invitation`, billing, and audit attribution.

## Consequences

The database design remains compatible with Option A. Laravel still must implement a narrow identity adapter and avoid assuming that UI state is authorization. SSO is not an HSE launch dependency, but the chosen Auth provider must support the target customers' SSO requirements or a future identity decision will be needed. Operations can reuse the same identity, tenant, and authorization model without sharing module permissions by default.

## References

- [Supabase Auth sessions](https://supabase.com/docs/guides/auth/sessions)
- [Supabase Auth MFA](https://supabase.com/docs/guides/auth/auth-mfa)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Laravel authentication](https://laravel.com/framework/docs/13.x/authentication)
- [Laravel password reset](https://laravel.com/framework/docs/13.x/passwords)
