# Proposal: delete policy for evidence objects (F-07, not applied)

Status: proposal only. Not a migration. Needs a decision from the Data Engineer and Mohamed.

Today no policy lets anyone delete an object in `sentriq-hse-evidence`, so an upload that is never confirmed stays forever.

Proposed scope, smallest that closes the gap:

1. A member may delete an object only while its `hse.evidence_files` row is `pending` and `uploaded_by = auth.uid()`, in their own tenant and site path (same tests as the upload policy). Confirmed evidence can never be deleted by a member.
2. Cleanup of pending rows older than 24 hours (row and object) runs as a scheduled job that is not a user action. pg_cron is not installed on TEST. Options: install pg_cron (needs the dashboard), or run the cleanup from the backend with a trusted job. Decision needed.
3. Audit: each cleanup writes one audit event. Audit rows are never deleted.

Sketch of the policy (for review, do not apply):

```sql
create policy sentriq_evidence_delete_pending on storage.objects for delete to authenticated using (
  bucket_id = 'sentriq-hse-evidence' and exists (
    select 1 from hse.evidence_files e
     where e.storage_key = storage.objects.name and e.uploaded_by = auth.uid() and e.status = 'pending'
       and e.tenant_id = private.path_uuid(split_part(storage.objects.name,'/',1))
       and e.site_id = private.path_uuid(split_part(storage.objects.name,'/',2))));
```

Tests it would need: uploader deletes own pending object (allowed); uploader deletes a confirmed object (refused); another member and another tenant (refused); anon (refused).
