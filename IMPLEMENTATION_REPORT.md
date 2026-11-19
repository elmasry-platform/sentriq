# SENTRIQ database implementation report

## Disposition

**PARTIALLY IMPLEMENTED — DATABASE RUNTIME VERIFICATION BLOCKED.** The forward migration, contract documentation, static check, CI workflow, and 42-assertion pgTAP suite are in the feature branch. The migration and pgTAP suite have not been executed because this workstation has no Supabase CLI or `psql`, and the Docker Desktop Linux engine is unavailable. Treat the SQL as unverified until CI or a local Supabase stack runs successfully.

## Scope delivered

- Added the commercial entitlement model for modules and features, plan versions, subscriptions and price snapshots, grants, usage events, invoices, invoice items, and payments. No prices or Copilot access are seeded.
- Preserved the legacy HSE entitlement table and added an idempotent, traceable backfill to module grants. Historical billing terms are not inferred; migrated grants are marked complimentary. Authenticated clients can no longer write legacy entitlement rows.
- Added normalized multi-role functional RBAC, separate company management levels, exact site/org-unit/task scopes, invitation token hash storage, and owner-only Subowner lifecycle controls.
- Added HSE and sensitive feature gates, service-role-only usage and billing RPCs, idempotency and quota checks, append-only audit/history protections, and the first-reviewer workflow transition correction.
- Documented the UI mapping and trusted-backend boundary. No UI files were changed; the current UI repository still uses mock dashboard data and browser `localStorage` for forms.
- Added a GitHub Actions workflow for static contract checks and disposable local Supabase migration/pgTAP execution.

## Verification

| Check | Result |
|---|---|
| Static database contract script | PASS — 20 required markers; flagged broad `FOR ALL` delete policies and browser access to usage recording are absent. |
| `git diff --check` | PASS — no whitespace errors; Git emitted only line-ending normalization warnings. |
| pgTAP assertion inventory | 42 planned assertions, matching `extensions.plan(42)`. |
| Supabase migration execution and database tests | BLOCKED — `supabase` and `psql` are not installed; Docker client 29.4.0 cannot connect to `dockerDesktopLinuxEngine`. |
| Hosted database changes | NONE. No hosted Supabase project was linked or modified. |

The CI database job runs `supabase start --exclude studio,imgproxy,edge-runtime,logflare,vector`, `supabase db reset --local`, then `supabase test db --local`. Its results are required before treating the migration as verified.

## Acceptance coverage represented in pgTAP

The current suite exercises compatibility between a legacy HSE entitlement and module-level authorization in fixtures, separation of HSE and Copilot licensing, exact membership grant isolation and expiry, functional role union without management-level escalation, duplicate and cross-tenant role rejection, task/site and org-unit scope intersection, first-reviewer approve/return flow, tenant RLS, employee role-management denial, hard-delete/audit protections, invitation hash-only storage and one-time acceptance, service-role usage idempotency and content rejection, and duplicate-safe invoice event pricing.

This is not a passing acceptance matrix: all database assertions remain unexecuted, and concurrency behavior, the full Owner/Subowner positive access matrix, subscription lifecycle edge cases, invitation expiry/revocation/mismatch cases, and the complete UI-to-live-API integration still need verification or implementation. A live Supabase adapter, email delivery, payment collection, and production pricing are outside this database-only change.

## Branch and environment

- Repository: `elmasry-platform/sentriq`
- Feature branch: `codex/platform-entitlements-rbac`
- Base: `main` at `b5a16e42ecabe1b4d7b1c16c46b2442bb3870efd`
- Environment: Windows / PowerShell; Docker Desktop client available, Linux engine unavailable; Supabase CLI and `psql` unavailable.
- This work is forward-only; the initial HSE migration was not rewritten.
