-- Rollback for the DRAFT 046. Restores the old behavior (uploader can set status directly).
begin;
drop function if exists api.confirm_evidence(uuid, uuid);
drop trigger if exists evidence_status_guard on hse.evidence_files;
drop function if exists private.guard_evidence_status();
commit;
