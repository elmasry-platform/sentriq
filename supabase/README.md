# SENTRIQ database

This directory contains the initial Supabase PostgreSQL schema for company tenancy, permissions, and the HSE module.

## First local or hosted setup

1. Create/link the Supabase project and apply `migrations/202611190001_sentriq_hse.sql` with the Supabase CLI.
2. Create the platform owner's Auth account. As the database operator (`postgres`), run:

   ```sql
   select private.bootstrap_platform_owner('<owner-auth-user-uuid>'::uuid);
   ```

   This is a one-time operation. Do not expose this function through the browser API.
3. The owner or a subowner creates a company with `api.create_tenant(name, industry_label, first_company_superadmin_auth_user_uuid)`. The tenant starts with HSE enabled.
4. Add `api`, `core`, `iam`, `hse`, and `audit` to the Supabase Data API exposed schemas as configured in `config.toml`. Keep `private` unexposed.
5. Keep the `sentriq-hse-evidence` bucket private. Insert pending evidence metadata first, then upload to `tenant_uuid/site_uuid/file_name`, then update that uploader's metadata status to `confirmed`. Storage policies require the metadata row and apply its tenant/site/task permissions.

## Current boundary

- Platform operators are separate from company memberships. Owner and subowner have cross-tenant access. Only the owner can manage subowners.
- Company superadmins can manage memberships, site access, task assignments, and member permission grants inside their company. Admins and employees receive only explicit permissions and scopes.
- A user account in Supabase Auth does not grant company access by itself. The company superadmin must add that existing Auth user to `iam.memberships` before the user can access tenant data. Invitation email delivery is not part of this first migration.
- Published forms and review/action histories are append-only. Inspection answers and mutable work records are JSONB/typed columns matching the UI contract.
- Review decisions are inserted into `hse.inspection_reviews`; a database trigger applies the matching workflow transition in the same transaction. Corrective-action status changes create `hse.action_updates` history rows automatically.
- The UI repository still uses mock JSON and local form storage. Wire its repository/service layer to the API views and table writes before expecting live data.
- This migration has not been deployed to a hosted project. Apply it in development and review authorization behavior before production data is stored.
