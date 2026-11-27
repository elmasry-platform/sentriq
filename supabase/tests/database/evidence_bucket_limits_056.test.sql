-- Evidence bucket limits (056): the bucket refuses files over 10 MB and types outside jpeg, png, webp and pdf; rollback restores no limits.
-- The migration and rollback copies below are checked against the files by scripts/check_database_contract.ps1.
begin;
select extensions.plan(8);
select extensions.is((select count(*)::int from storage.buckets where id='sentriq-hse-evidence'), 1, 'the evidence bucket exists');
-- BEGIN EMBEDDED 056 ROLLBACK
-- Rollback of 056: remove the size limit and the type allowlist from the evidence bucket (back to the 045 state).
update storage.buckets
   set file_size_limit = null,
       allowed_mime_types = null
 where id = 'sentriq-hse-evidence';
-- END EMBEDDED 056 ROLLBACK
select extensions.is((select file_size_limit from storage.buckets where id='sentriq-hse-evidence'), null::bigint, 'after rollback: no size limit');
select extensions.is((select allowed_mime_types from storage.buckets where id='sentriq-hse-evidence'), null::text[], 'after rollback: no type allowlist');
-- BEGIN EMBEDDED 056
-- 056: size limit and type allowlist on the evidence bucket (security review v2, F-07).
-- Storage now refuses a file over 10 MB (same limit as the form builder) and any type outside images (jpeg, png, webp) and PDF.
-- application/octet-stream is not in the list, so the 046 tradeoff (octet-stream accepted by the confirm check) can no longer be used to upload an arbitrary file.
-- Bucket settings only. No policy, table or data change. Existing objects are not touched.
-- Rollback: supabase/rollbacks/202611250056_evidence_bucket_limits.rollback.sql. Plain PostgreSQL.
update storage.buckets
   set file_size_limit = 10485760,
       allowed_mime_types = array['image/jpeg','image/png','image/webp','application/pdf']
 where id = 'sentriq-hse-evidence';
-- END EMBEDDED 056
select extensions.is((select file_size_limit from storage.buckets where id='sentriq-hse-evidence'), 10485760::bigint, 'size limit is 10 MB');
select extensions.is((select allowed_mime_types from storage.buckets where id='sentriq-hse-evidence'), array['image/jpeg','image/png','image/webp','application/pdf'], 'allowlist is jpeg, png, webp, pdf');
select extensions.ok(not coalesce((select allowed_mime_types from storage.buckets where id='sentriq-hse-evidence') @> array['application/octet-stream'], false), 'octet-stream is not allowed');
select extensions.ok(not coalesce((select allowed_mime_types from storage.buckets where id='sentriq-hse-evidence') @> array['text/html'], false), 'html is not allowed');
select extensions.is((select public from storage.buckets where id='sentriq-hse-evidence'), false, 'the bucket stays private');
select * from extensions.finish();
rollback;
