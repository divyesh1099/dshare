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

## Large transfers

Run Gunicorn with `gunicorn.conf.py` (also discovered automatically from the
repository root). Threaded workers keep heartbeating during long transfers;
Railway's start command must not select synchronous workers. Public and private
downloads support HEAD and single byte ranges for resume, stream at most 1 MiB
per read, and still authorize every request without exposing storage URLs.
Large web uploads use 8 MiB resumable chunks and never fall back to a whole-file
POST. Completion retries retain a receipt for the upload-session TTL; concurrent
completion requests are serialized across workers. Replacement files get unique
keys and the previous file is deleted only after the new file is saved.
Chunk sessions currently use local disk: keep one service replica. A restart or
deployment can discard unfinished chunks; select the file again to restart.
