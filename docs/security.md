---
title: Security
---

# Security

## Public mode

Public mode is intentionally “truly public”: anyone who can access the URL can upload/download/clear the public slot.

This is convenient, but risky.

### Risks

- overwriting your public slot
- spam uploads / spam clears
- illegal content uploads

### Mitigations

- keep public TTL short (`DSHARE_PUBLIC_TTL_SECONDS`)
- keep file size small (`DSHARE_PUBLIC_MAX_UPLOAD_BYTES`)
- keep throttle limits low (`DSHARE_PUBLIC_UPLOAD_LIMIT`, `DSHARE_PUBLIC_CLEAR_LIMIT`)
- deploy behind a WAF / Cloudflare
- consider access restriction (VPN, IP allowlist, basic auth at reverse proxy)

## Private mode

Private mode isolates stored content per verified user, and sessions last ~30 days by default.

Note: DShare is not end‑to‑end encrypted; the server can see files/text.

## Private account access

Private share reads, writes, clearing, and chunked uploads require an active,
email-verified account. Account ownership checks also apply to upload sessions.
Private responses use `Cache-Control: private, no-store, no-cache, max-age=0`.
Passkeys require authenticator user verification (such as a device PIN or biometric).
Production session and CSRF cookies require HTTPS; session cookies are HttpOnly.

Files download as attachments through `/download/` rather than exposing storage
URLs. Django does not serve `/media/` directly, including during development.
Keep the object-storage bucket private and do not expose MEDIA_ROOT through a
web server/CDN. Previously issued storage URLs remain usable until their expiry;
this code change cannot revoke them. Downloads now stream through the application
in bounded chunks, so large files consume application bandwidth and worker time
without being buffered in full in worker memory.
Anonymous public sharing is still available and is separate from private accounts.

## Large transfers and private preference

Production limits are 10 GiB per private file and 1 GiB per public file.
Run Gunicorn with `gunicorn.conf.py`; two threaded workers each have eight
threads. A service-wide gate permits four public transfers at once across
workers, reserving the remaining worker capacity for verified private users.
Private uploads use six parallel chunks; public uploads use four. Public callers
receive Retry-After when slots are busy; browser uploads back off automatically
and browser downloads retry from a small waiting page. This reserves server
capacity; it does not guarantee priority on the user's ISP or storage network.

Object-storage uploads write each 8 MiB chunk as an S3 multipart part. Completion
commits an ordered part list, eliminating whole-file local staging and the
second full-file upload. Part receipts are persisted with DB row locking and
resume across worker restarts/deployments. Completion retries recover even if
storage committed before a response or DB failure. Expired incomplete uploads
are aborted during session cleanup. Keys are unique, filenames use the FileField
length limit, and the previous file is deleted only after replacement is saved.

Public and private downloads authorize every request, support HEAD and single
byte ranges, and never expose storage URLs. Large object downloads prefetch a
bounded window of 4 MiB storage ranges (three for private, two for public), pin
the original ETag with If-Match, preserve byte order, and emit at most 1 MiB per
block. Worker memory does not grow with total file size.

Existing disk-based sessions and local development retain the old chunk path.
Those unfinished chunks remain tied to local disk and may be lost on a deploy.
Keep a single service replica for the public transfer gate and legacy sessions.

Large browser downloads open a save-to-disk page. Chrome/Edge desktop fetch
4 MiB authenticated byte ranges, keep at most four private/two public chunks
in flight, and write in order to the File System Access API. This avoids
Railway's per-request time cap without assembling the full file in browser
memory. Pause closes and saves the confirmed prefix; Resume continues from
that offset while the page remains open. Each request checks an opaque source
version and fails if the shared file changes. Browsers without the save API
retain native downloads and HTTP range resume. Direct API clients retain raw
streaming; `?raw=1` also explicitly selects it.
