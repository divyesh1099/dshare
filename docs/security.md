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
this code change cannot revoke them. Downloads now pass through the application,
so large files consume application bandwidth and storage-backend resources.
Anonymous public sharing is still available and is separate from private accounts.
