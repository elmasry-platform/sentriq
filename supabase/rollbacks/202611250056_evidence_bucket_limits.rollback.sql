-- Rollback of 056: remove the size limit and the type allowlist from the evidence bucket (back to the 045 state).
update storage.buckets
   set file_size_limit = null,
       allowed_mime_types = null
 where id = 'sentriq-hse-evidence';
