-- DRAFT, not applied anywhere. Needs approval before any TEST apply.
-- Problem: the uploader can set hse.evidence_files.status = 'confirmed' directly (insert or update),
-- with no check that the object exists in storage. The storage read policy treats confirmed as readable.
-- Fix: direct writes can only create 'pending' rows. Confirmation goes through api.confirm_evidence,
-- which checks the caller's upload permission on the site and that the object is stored.
-- No data change. Existing rows are not touched.
-- ACCEPTED TRADEOFF: application/octet-stream from storage is accepted, so the mime check can be bypassed by uploading
-- under that type. The mime check is therefore not a security control. Mitigation lives outside the database: serve
-- uploads with safe download headers (Content-Disposition: attachment, X-Content-Type-Options: nosniff) and never
-- render an upload inline.

create or replace function private.guard_evidence_status() returns trigger
language plpgsql set search_path = '' as $$
begin
  -- Runs as the caller (not SECURITY DEFINER), so current_user is the API role for direct writes
  -- and the function owner when called from api.confirm_evidence.
  if current_user in ('authenticated', 'anon') then
    if tg_op = 'INSERT' and new.status is distinct from 'pending' then
      raise exception 'evidence status is set by confirmation only' using errcode = '42501';
    elsif tg_op = 'UPDATE' and new.status is distinct from old.status then
      raise exception 'evidence status is set by confirmation only' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists evidence_status_guard on hse.evidence_files;
create trigger evidence_status_guard before insert or update of status on hse.evidence_files
  for each row execute function private.guard_evidence_status();

create or replace function api.confirm_evidence(p_tenant_id uuid, p_evidence_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare e hse.evidence_files%rowtype; v_rows integer; o record;
begin
  if auth.uid() is null then raise exception 'insufficient_privilege' using errcode = '42501'; end if;
  -- Lock the row so two concurrent confirmations run one after the other.
  select * into e from hse.evidence_files where id = p_evidence_id and tenant_id = p_tenant_id for update;
  if e.id is null
     or e.uploaded_by is distinct from auth.uid()
     or not private.can_access_hse(e.tenant_id, 'hse.evidence.upload', e.site_id, true, e.linked_record_type, e.linked_record_id) then
    raise exception 'insufficient_privilege' using errcode = '42501';
  end if;
  if e.status <> 'pending' then
    raise exception 'evidence is not pending' using errcode = '22023';
  end if;
  select * into o from storage.objects where bucket_id = 'sentriq-hse-evidence' and name = e.storage_key;
  if o.id is null then
    raise exception 'evidence object is not stored' using errcode = '22023';
  end if;
  -- The stored object must be the one this user uploaded and match what the row declares.
  -- owner_id (text) is the current Supabase column, owner (uuid) the older one. The mime type is compared as a base type
  -- (charset suffix ignored). application/octet-stream is accepted because storage reports it when the client set no type;
  -- that case is weaker, so the size and owner checks carry the weight there.
  if coalesce(o.owner_id, o.owner::text) is distinct from auth.uid()::text
     or (o.metadata ->> 'size') is distinct from e.size_bytes::text
     or lower(btrim(split_part(coalesce(o.metadata ->> 'mimetype', ''), ';', 1)))
          not in (lower(btrim(split_part(e.mime_type, ';', 1))), 'application/octet-stream') then
    raise exception 'evidence object does not match the record' using errcode = '22023';
  end if;
  update hse.evidence_files set status = 'confirmed' where id = e.id and status = 'pending';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then
    raise exception 'evidence is not pending' using errcode = '22023';
  end if;
  insert into audit.events(tenant_id, actor_user_id, scope_kind, action_key, record_type, record_id, summary)
  values (e.tenant_id, auth.uid(), 'tenant', 'hse.evidence.confirmed', 'hse.evidence_files', e.id,
          jsonb_build_object('storage_key', e.storage_key));
end $$;

revoke all on function api.confirm_evidence(uuid, uuid) from public, anon, service_role;
grant execute on function api.confirm_evidence(uuid, uuid) to authenticated;
revoke all on function private.guard_evidence_status() from public, anon, authenticated;
