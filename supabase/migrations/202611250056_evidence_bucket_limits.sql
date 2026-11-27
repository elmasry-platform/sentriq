-- 056: size limit and type allowlist on the evidence bucket (security review v2, F-07).
-- Storage now refuses a file over 10 MB (same limit as the form builder) and any type outside images (jpeg, png, webp) and PDF.
-- application/octet-stream is not in the list, so the 046 tradeoff (octet-stream accepted by the confirm check) can no longer be used to upload an arbitrary file.
-- Bucket settings only. No policy, table or data change. Existing objects are not touched.
-- Rollback: supabase/rollbacks/202611250056_evidence_bucket_limits.rollback.sql. Plain PostgreSQL.
update storage.buckets
   set file_size_limit = 10485760,
       allowed_mime_types = array['image/jpeg','image/png','image/webp','application/pdf']
 where id = 'sentriq-hse-evidence';
