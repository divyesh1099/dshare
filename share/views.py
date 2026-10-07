import json
import logging
import math
import os
import shutil
import tempfile
from functools import wraps
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files import File
from django.core.files.storage import default_storage
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.contrib.auth.hashers import check_password, make_password
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.cache import patch_cache_control
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST
try:
    from fido2.server import Fido2Server
    from fido2.utils import websafe_decode
    from fido2.webauthn import (
        AttestedCredentialData,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    _FIDO2_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover
    Fido2Server = None  # type: ignore[assignment]
    websafe_decode = None  # type: ignore[assignment]
    AttestedCredentialData = None  # type: ignore[assignment]
    PublicKeyCredentialRpEntity = None  # type: ignore[assignment]
    PublicKeyCredentialUserEntity = None  # type: ignore[assignment]
    ResidentKeyRequirement = None  # type: ignore[assignment]
    UserVerificationRequirement = None  # type: ignore[assignment]
    _FIDO2_AVAILABLE = False

from .models import (
    EmailVerificationToken,
    PublicShareState,
    UploadSession,
    UserProfile,
    UserShareState,
    WebAuthnCredential,
)

User = get_user_model()
logger = logging.getLogger(__name__)


def _private_access(view):
    """Keep anonymous public sharing, but fail closed for unverified accounts."""
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if request.user.is_authenticated:
            if not request.user.is_active or not UserProfile.objects.filter(
                user=request.user, email_verified_at__isnull=False
            ).exists():
                response = JsonResponse({"status": "fail", "code": "verification_required"}, status=403)
            else:
                response = view(request, *args, **kwargs)
            patch_cache_control(response, private=True, no_store=True, no_cache=True, max_age=0)
            response["Pragma"] = "no-cache"
            response["X-Content-Type-Options"] = "nosniff"
            return response
        return view(request, *args, **kwargs)
    return wrapped


def _parse_json(request: HttpRequest) -> dict:
    try:
        return json.loads(request.body.decode("utf-8") or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _client_ip(request: HttpRequest) -> str:
    # If behind a proxy, configure SECURE_PROXY_SSL_HEADER / USE_X_FORWARDED_HOST.
    return request.META.get("REMOTE_ADDR") or "0.0.0.0"


def _get_rp_id(request: HttpRequest) -> str:
    configured = getattr(settings, "DSHARE_RP_ID", None)
    if configured:
        return configured
    return request.get_host().split(":", 1)[0]


def _get_rp_name() -> str:
    return getattr(settings, "DSHARE_RP_NAME", "DShare")


def _get_fido_server(request: HttpRequest) -> Fido2Server:
    if not _FIDO2_AVAILABLE:  # pragma: no cover
        raise RuntimeError("WebAuthn unavailable (missing fido2)")
    rp = PublicKeyCredentialRpEntity(id=_get_rp_id(request), name=_get_rp_name())
    return Fido2Server(rp)


def _get_or_create_profile(user) -> UserProfile:
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def _debug_email_allowed(request: HttpRequest, data: dict | None = None) -> bool:
    if settings.DEBUG:
        return True
    token = getattr(settings, "DSHARE_ADMIN_TOKEN", "")
    if not token:
        return False
    provided = request.headers.get("X-Dshare-Admin-Token")
    if not provided and data:
        provided = data.get("token")
    return provided == token


def _send_email_message(
    *,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    def send_via_resend_api() -> None:
        api_key = getattr(settings, "RESEND_API_KEY", "")
        if not api_key:
            raise RuntimeError("RESEND_API_KEY is not set")
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None)
        if not from_email:
            raise RuntimeError("DEFAULT_FROM_EMAIL is not set")
        payload = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
            "html": html_body,
        }
        data = json.dumps(payload).encode("utf-8")
        req = Request(
            "https://api.resend.com/emails",
            data=data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        timeout = getattr(settings, "EMAIL_TIMEOUT", 15)
        try:
            with urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                if status and status >= 400:
                    body = resp.read().decode("utf-8", errors="replace")
                    raise RuntimeError(f"Resend API error {status}: {body[:500]}")
        except HTTPError as exc:
            body = ""
            if exc.fp:
                body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Resend API error {exc.code}: {body[:500]}")
        except URLError as exc:
            raise RuntimeError(f"Resend API request failed: {exc}")

    provider = getattr(settings, "DSHARE_EMAIL_PROVIDER", "smtp")
    if provider == "resend":
        logger.info(
            f"Sending email to {to_email} via Resend API Timeout={settings.EMAIL_TIMEOUT}"
        )
        send_via_resend_api()
        return

    if not getattr(settings, "DSHARE_EMAIL_CONFIGURED", True):
        raise RuntimeError(
            "SMTP backend selected but EMAIL_HOST is not set. "
            "Configure SMTP or use the console email backend."
        )

    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
        to=[to_email],
    )
    message.attach_alternative(html_body, "text/html")
    try:
        logger.info(
            f"Sending email to {to_email} via {settings.EMAIL_HOST}:{settings.EMAIL_PORT} "
            f"(SSL={settings.EMAIL_USE_SSL}, TLS={settings.EMAIL_USE_TLS}) "
            f"Timeout={settings.EMAIL_TIMEOUT}"
        )
        message.send(fail_silently=False)
    except Exception:
        if getattr(settings, "RESEND_API_KEY", ""):
            logger.info("SMTP failed; retrying via Resend API")
            send_via_resend_api()
            return
        logger.exception("Failed to send verification email")
        raise


@require_POST
def api_auth_email_status(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    email = (data.get("email") or "").strip().lower()
    if not email:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({"status": "fail"}, status=400)

    ip = _client_ip(request)
    throttle_key = f"dshare:email_status:{ip}"
    attempts = cache.get(throttle_key, 0)
    if attempts >= 120:
        return JsonResponse({"status": "fail"}, status=429)
    cache.set(throttle_key, attempts + 1, timeout=60 * 10)

    can_login = False
    user = User.objects.filter(username=email).first()
    if user and user.is_active:
        profile = _get_or_create_profile(user)
        can_login = profile.email_verified_at is not None

    return JsonResponse({"status": "ok", "can_login": can_login})


def _send_verification_email(*, request: HttpRequest, user, token: str) -> None:
    verify_url = request.build_absolute_uri(
        reverse("auth_verify_email", kwargs={"token": token})
    )
    subject = "DShare"
    text_body = f"Verify: {verify_url}"
    html_body = f"""
<!doctype html>
<html>
  <head>
    <meta name="color-scheme" content="dark">
    <meta name="supported-color-schemes" content="dark">
  </head>
  <body style="margin:0;padding:0;background:#000;color:#000;font-family:Arial, sans-serif;">
    <a href="{verify_url}" style="display:block;width:100%;padding:24px;background:#000;color:#000;text-decoration:none;">
      Verify
    </a>
  </body>
</html>
""".strip()

    _send_email_message(
        to_email=user.email,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


@ensure_csrf_cookie
def home_view(request):
    return render(request, "share/home.html")


@csrf_exempt
@require_POST
def api_debug_email(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    if not _debug_email_allowed(request, data):
        return JsonResponse({"status": "fail", "code": "forbidden"}, status=403)

    email = (data.get("to") or data.get("email") or "").strip().lower()
    if not email:
        return JsonResponse({"status": "fail", "code": "missing_email"}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({"status": "fail", "code": "invalid_email"}, status=400)

    subject = "DShare test email"
    text_body = "DShare email test. If you received this, email delivery works."
    html_body = """
<!doctype html>
<html>
  <body style="margin:0;padding:0;font-family:Arial, sans-serif;">
    <p>DShare email test. If you received this, email delivery works.</p>
  </body>
</html>
""".strip()

    try:
        _send_email_message(
            to_email=email,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )
    except Exception as exc:
        payload = {"status": "fail", "code": "email_send_failed"}
        if settings.DEBUG:
            payload["detail"] = str(exc)[:500]
        return JsonResponse(payload, status=502)

    return JsonResponse({"status": "ok", "to": email})


@require_POST
def api_auth_register(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    pin = data.get("pin") or ""

    if not email:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({"status": "fail"}, status=400)

    if not password:
        return JsonResponse({"status": "fail"}, status=400)

    ip = _client_ip(request)
    throttle_key = f"dshare:register:{ip}"
    attempts = cache.get(throttle_key, 0)
    if attempts >= 10:
        return JsonResponse({"status": "fail"}, status=429)
    cache.set(throttle_key, attempts + 1, timeout=60 * 10)

    user = User.objects.filter(username=email).first()
    if user is None:
        user = User(username=email, email=email)
        user.set_unusable_password()
        user.save()

    _get_or_create_profile(user)

    EmailVerificationToken.objects.filter(user=user, used_at__isnull=True).delete()
    token_obj = EmailVerificationToken.objects.create(
        user=user,
        pending_password_hash=make_password(password),
        pending_pin_hash=make_password(pin) if pin else None,
    )
    try:
        _send_verification_email(request=request, user=user, token=token_obj.token)
    except Exception as exc:
        token_obj.delete()
        payload = {"status": "fail", "code": "email_send_failed"}
        if settings.DEBUG:
            payload["detail"] = str(exc)[:500]
        return JsonResponse(payload, status=502)

    return JsonResponse({"status": "ok"})


@require_GET
def verify_email_view(request: HttpRequest, token: str) -> HttpResponse:
    max_age_seconds = int(getattr(settings, "DSHARE_EMAIL_TOKEN_MAX_AGE_SECONDS", 86400))
    token_obj = (
        EmailVerificationToken.objects.select_related("user")
        .filter(token=token)
        .first()
    )
    if (
        token_obj is None
        or token_obj.used_at is not None
        or token_obj.is_expired(max_age_seconds=max_age_seconds)
    ):
        return redirect("home")

    now = timezone.now()
    token_obj.used_at = now
    token_obj.save(update_fields=["used_at"])

    profile = _get_or_create_profile(token_obj.user)
    if profile.email_verified_at is None:
        profile.email_verified_at = now
        profile.save(update_fields=["email_verified_at"])

    did_apply = False
    if token_obj.pending_password_hash:
        token_obj.user.password = token_obj.pending_password_hash
        token_obj.user.save(update_fields=["password"])
        did_apply = True
    if token_obj.pending_pin_hash:
        profile.pin_hash = token_obj.pending_pin_hash
        profile.save(update_fields=["pin_hash"])
        did_apply = True
    if did_apply:
        token_obj.pending_password_hash = None
        token_obj.pending_pin_hash = None
        token_obj.save(update_fields=["pending_password_hash", "pending_pin_hash"])

    login(request, token_obj.user, backend="django.contrib.auth.backends.ModelBackend")

    url = f'{reverse("home")}?{urlencode({"verified": "1"})}'
    return redirect(url)


@require_POST
def api_auth_password_login(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    email = (data.get("email") or "").strip().lower()
    secret = data.get("secret") or data.get("password") or data.get("pin") or ""
    if not email:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({"status": "fail"}, status=400)

    ip = _client_ip(request)
    throttle_key = f"dshare:login_fail:{ip}"
    attempts = cache.get(throttle_key, 0)
    if attempts >= 50:
        return JsonResponse({"status": "fail"}, status=429)

    if not secret:
        return JsonResponse({"status": "fail"}, status=400)

    user = User.objects.filter(username=email).first()
    if user is None or not user.is_active:
        cache.set(throttle_key, attempts + 1, timeout=60 * 10)
        return JsonResponse({"status": "fail"}, status=401)

    auth_user = authenticate(request, username=email, password=secret)
    if auth_user is None:
        profile = _get_or_create_profile(user)
        if not profile.pin_hash or not check_password(secret, profile.pin_hash):
            cache.set(throttle_key, attempts + 1, timeout=60 * 10)
            return JsonResponse({"status": "fail"}, status=401)
        auth_user = user

    profile = _get_or_create_profile(auth_user)
    if profile.email_verified_at is None:
        cache.set(throttle_key, attempts + 1, timeout=60 * 10)
        return JsonResponse({"status": "fail"}, status=403)

    login(request, auth_user)
    cache.delete(throttle_key)
    return JsonResponse({"status": "ok"})


@require_POST
def api_auth_set_credentials(request: HttpRequest) -> JsonResponse:
    if not request.user.is_authenticated:
        return JsonResponse({"status": "fail"}, status=401)

    profile = _get_or_create_profile(request.user)
    if profile.email_verified_at is None:
        return JsonResponse({"status": "fail"}, status=403)

    data = _parse_json(request)
    password = data.get("password") or ""
    pin = data.get("pin") or ""
    if not password:
        return JsonResponse({"status": "fail"}, status=400)

    request.user.password = make_password(password)
    request.user.save(update_fields=["password"])

    profile.pin_hash = make_password(pin) if pin else None
    profile.save(update_fields=["pin_hash"])

    login(
        request,
        request.user,
        backend="django.contrib.auth.backends.ModelBackend",
    )
    return JsonResponse({"status": "ok"})


@require_POST
def api_auth_logout(request: HttpRequest) -> JsonResponse:
    logout(request)
    return JsonResponse({"status": "ok"})


@require_GET
def api_auth_me(request: HttpRequest) -> JsonResponse:
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False})

    profile = _get_or_create_profile(request.user)
    return JsonResponse(
        {
            "authenticated": True,
            "email": request.user.email or request.user.username,
            "email_verified": profile.email_verified_at is not None,
            "has_passkey": request.user.webauthn_credentials.exists(),
            "has_password": request.user.has_usable_password(),
            "has_pin": bool(profile.pin_hash),
        }
    )


@require_POST
def api_webauthn_register_begin(request: HttpRequest) -> JsonResponse:
    if not _FIDO2_AVAILABLE:
        return JsonResponse({"status": "fail", "code": "webauthn_unavailable"}, status=503)

    if not request.user.is_authenticated:
        return JsonResponse({"status": "fail"}, status=401)

    profile = _get_or_create_profile(request.user)
    if profile.email_verified_at is None:
        return JsonResponse({"status": "fail"}, status=403)

    server = _get_fido_server(request)
    user_handle = profile.ensure_webauthn_user_id()
    user_entity = PublicKeyCredentialUserEntity(
        id=user_handle, name=request.user.username, display_name=request.user.username
    )
    existing = [
        AttestedCredentialData(bytes(c.credential_data))
        for c in request.user.webauthn_credentials.all()
    ]
    options, state = server.register_begin(
        user_entity,
        credentials=existing,
        resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    request.session["webauthn_register_state"] = state
    return JsonResponse(dict(options))


@require_POST
@_private_access
def api_webauthn_register_complete(request: HttpRequest) -> JsonResponse:
    if not _FIDO2_AVAILABLE:
        return JsonResponse({"status": "fail", "code": "webauthn_unavailable"}, status=503)

    if not request.user.is_authenticated:
        return JsonResponse({"status": "fail"}, status=401)

    state = request.session.pop("webauthn_register_state", None)
    if not state:
        return JsonResponse({"status": "fail"}, status=400)

    data = _parse_json(request)
    server = _get_fido_server(request)
    try:
        auth_data = server.register_complete(state, data)
    except Exception:
        return JsonResponse({"status": "fail"}, status=400)

    if auth_data.credential_data is None:
        return JsonResponse({"status": "fail"}, status=400)

    credential_id = auth_data.credential_data.credential_id
    credential_data = bytes(auth_data.credential_data)
    existing = WebAuthnCredential.objects.filter(credential_id=credential_id).first()
    if existing and existing.user_id != request.user.id:
        return JsonResponse({"status": "fail"}, status=400)
    if not existing:
        WebAuthnCredential.objects.create(
            user=request.user,
            credential_id=credential_id,
            credential_data=credential_data,
        )
    return JsonResponse({"status": "ok"})


@require_POST
def api_webauthn_auth_begin(request: HttpRequest) -> JsonResponse:
    if not _FIDO2_AVAILABLE:
        return JsonResponse({"status": "fail", "code": "webauthn_unavailable"}, status=503)

    server = _get_fido_server(request)
    options, state = server.authenticate_begin(
        user_verification=UserVerificationRequirement.REQUIRED
    )
    request.session["webauthn_auth_state"] = state
    return JsonResponse(dict(options))


@require_POST
def api_webauthn_auth_complete(request: HttpRequest) -> JsonResponse:
    if not _FIDO2_AVAILABLE:
        return JsonResponse({"status": "fail", "code": "webauthn_unavailable"}, status=503)

    state = request.session.pop("webauthn_auth_state", None)
    if not state:
        return JsonResponse({"status": "fail"}, status=400)

    data = _parse_json(request)
    raw_id = data.get("rawId") or data.get("id")
    if not raw_id:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        credential_id = websafe_decode(raw_id)
    except Exception:
        return JsonResponse({"status": "fail"}, status=400)

    credential = (
        WebAuthnCredential.objects.select_related("user")
        .filter(credential_id=credential_id)
        .first()
    )
    if credential is None or not credential.user.is_active:
        return JsonResponse({"status": "fail"}, status=401)

    server = _get_fido_server(request)
    stored = AttestedCredentialData(bytes(credential.credential_data))
    try:
        server.authenticate_complete(state, [stored], data)
    except Exception:
        return JsonResponse({"status": "fail"}, status=401)

    if not UserProfile.objects.filter(
        user=credential.user, email_verified_at__isnull=False
    ).exists():
        return JsonResponse({"status": "fail"}, status=403)

    login(
        request,
        credential.user,
        backend="django.contrib.auth.backends.ModelBackend",
    )
    credential.last_used_at = timezone.now()
    credential.save(update_fields=["last_used_at"])
    return JsonResponse({"status": "ok"})


def _file_size(uploaded_file) -> int:
    try:
        return int(uploaded_file.size)
    except Exception:
        return 0


def _delete_field_file(field_file) -> None:
    if not field_file:
        return
    try:
        logger.info(f"Deleting old file: {field_file.name}")
        field_file.delete(save=False)
    except Exception as e:
        logger.error(f"Failed to delete file {field_file.name}: {e}")


def _get_or_create_user_share(user) -> UserShareState:
    share, _ = UserShareState.objects.get_or_create(user=user)
    return share


def _get_or_create_public_share() -> PublicShareState:
    share, _ = PublicShareState.objects.get_or_create(pk=1)
    return share


def _maybe_expire_share(*, share, ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        return
    if share.updated_at >= timezone.now() - timezone.timedelta(seconds=ttl_seconds):
        return

    if share.file:
        _delete_field_file(share.file)
    share.file = None
    share.text = None
    share.save(update_fields=["file", "text", "updated_at"])


def _upload_chunk_root() -> str:
    base_dir = getattr(settings, "MEDIA_ROOT", None)
    if base_dir:
        return os.path.join(base_dir, ".dshare_chunks")
    return os.path.join(tempfile.gettempdir(), "dshare_chunks")


def _upload_session_dir(session_id: str) -> str:
    return os.path.join(_upload_chunk_root(), session_id)


def _upload_chunk_path(session_id: str, index: int) -> str:
    return os.path.join(_upload_session_dir(session_id), f"{index:06d}.part")


def _upload_v2_marker_path(session_id: str) -> str:
    return os.path.join(_upload_session_dir(session_id), ".v2")


def _upload_data_path(session_id: str) -> str:
    return os.path.join(_upload_session_dir(session_id), "data.bin")


def _upload_done_marker_path(session_id: str, index: int) -> str:
    return os.path.join(_upload_session_dir(session_id), f"{index:06d}.done")


def _ensure_upload_v2_marker(session_id: str) -> None:
    marker_path = _upload_v2_marker_path(session_id)
    if os.path.exists(marker_path):
        return
    try:
        with open(marker_path, "wb"):
            pass
    except OSError:
        logger.exception("Failed to create v2 upload marker")


def _scan_received_chunk_indices(
    session_id: str,
    *,
    suffix: str,
    total_chunks: int,
    chunk_size: int,
    total_size: int,
) -> list[int]:
    session_dir = _upload_session_dir(session_id)
    received: set[int] = set()
    try:
        with os.scandir(session_dir) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                name = entry.name
                if not name.endswith(suffix):
                    continue
                stem = name[: -len(suffix)]
                try:
                    idx = int(stem)
                except ValueError:
                    continue
                if not (0 <= idx < total_chunks):
                    continue

                if suffix == ".part":
                    # Validate size to avoid treating partial files as "received".
                    expected = total_size - (idx * chunk_size)
                    expected = min(chunk_size, max(0, expected))
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        continue
                    if expected <= 0 or size != expected:
                        try:
                            os.remove(entry.path)
                        except OSError:
                            pass
                        continue

                received.add(idx)
    except FileNotFoundError:
        return []
    except OSError:
        logger.exception("Failed to scan received chunks")
        return []

    return sorted(received)


def _expected_chunk_size(session: UploadSession, index: int) -> int:
    offset = index * session.chunk_size
    remaining = session.total_size - offset
    if remaining <= 0:
        return 0
    return min(session.chunk_size, remaining)


def _open_upload_data_file(path: str):
    try:
        return open(path, "r+b")
    except FileNotFoundError:
        try:
            return open(path, "x+b")
        except FileExistsError:
            return open(path, "r+b")


def _touch_upload_session(session: UploadSession) -> None:
    # Avoid a DB write for every chunk; once per ~30s is plenty to prevent
    # long-running uploads from being cleaned up as "expired".
    key = f"dshare:upload_touch:{session.id}"
    try:
        should_touch = cache.add(key, "1", timeout=30)
    except Exception:
        should_touch = True
    if not should_touch:
        return
    try:
        UploadSession.objects.filter(id=session.id).update(updated_at=timezone.now())
    except Exception:
        logger.exception("Failed to touch upload session")


def _delete_upload_session_files(session: UploadSession) -> None:
    try:
        shutil.rmtree(_upload_session_dir(str(session.id)), ignore_errors=True)
    except Exception:
        logger.exception("Failed to delete upload session files")


def _cleanup_expired_upload_sessions() -> None:
    ttl_seconds = int(
        getattr(settings, "DSHARE_UPLOAD_SESSION_TTL_SECONDS", 60 * 60 * 24)
    )
    if ttl_seconds <= 0:
        return
    cutoff = timezone.now() - timezone.timedelta(seconds=ttl_seconds)
    expired = UploadSession.objects.filter(updated_at__lt=cutoff)
    for session in expired:
        _delete_upload_session_files(session)
    expired.delete()


@require_POST
@_private_access
def api_upload_start(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    filename = (data.get("filename") or "").strip()
    total_size = int(data.get("size") or 0)
    content_type = (data.get("content_type") or "").strip()
    default_chunk_size = int(
        getattr(settings, "DSHARE_UPLOAD_DEFAULT_CHUNK_BYTES", 8 * 1024 * 1024)
    )
    max_chunk_size = int(
        getattr(settings, "DSHARE_UPLOAD_MAX_CHUNK_BYTES", 32 * 1024 * 1024)
    )
    min_chunk_size = int(
        getattr(settings, "DSHARE_UPLOAD_MIN_CHUNK_BYTES", 256 * 1024)
    )
    chunk_size = int(data.get("chunk_size") or 0) or default_chunk_size
    upload_id = (data.get("upload_id") or "").strip()

    if not filename or total_size <= 0:
        return JsonResponse({"status": "fail"}, status=400)

    chunk_size = max(min_chunk_size, min(chunk_size, max_chunk_size))

    max_bytes = int(
        getattr(
            settings,
            "DSHARE_PUBLIC_MAX_UPLOAD_BYTES"
            if not request.user.is_authenticated
            else "DSHARE_USER_MAX_UPLOAD_BYTES",
            10 * 1024 * 1024,
        )
    )
    if total_size > max_bytes:
        return JsonResponse({"status": "fail"}, status=413)

    _cleanup_expired_upload_sessions()

    is_public = not request.user.is_authenticated
    user = None if is_public else request.user

    session = None
    if upload_id:
        try:
            session = UploadSession.objects.get(id=upload_id)
        except (UploadSession.DoesNotExist, ValueError):
            session = None
        if session:
            if session.is_public != is_public or session.user_id != (user.id if user else None):
                session = None
            elif (
                session.filename != filename
                or session.total_size != total_size
                or session.chunk_size != chunk_size
            ):
                session = None

    total_chunks = max(1, math.ceil(total_size / chunk_size))
    if session is None:
        session = UploadSession.objects.create(
            user=user,
            is_public=is_public,
            filename=filename,
            content_type=content_type,
            total_size=total_size,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            received_chunks=[],
        )

    session_dir = _upload_session_dir(str(session.id))
    os.makedirs(session_dir, exist_ok=True)

    legacy_received = _scan_received_chunk_indices(
        str(session.id),
        suffix=".part",
        total_chunks=total_chunks,
        chunk_size=session.chunk_size,
        total_size=session.total_size,
    )
    received_chunks = legacy_received
    if not legacy_received:
        _ensure_upload_v2_marker(str(session.id))
        received_chunks = _scan_received_chunk_indices(
            str(session.id),
            suffix=".done",
            total_chunks=total_chunks,
            chunk_size=session.chunk_size,
            total_size=session.total_size,
        )

    session.received_chunks = received_chunks
    session.total_chunks = total_chunks
    session.save(update_fields=["received_chunks", "total_chunks", "updated_at"])

    return JsonResponse(
        {
            "status": "ok",
            "upload_id": str(session.id),
            "chunk_size": session.chunk_size,
            "total_chunks": session.total_chunks,
            "received_chunks": session.received_chunks,
        }
    )


@require_POST
@_private_access
def api_upload_chunk(request: HttpRequest) -> JsonResponse:
    upload_id = (request.POST.get("upload_id") or "").strip()
    index_raw = request.POST.get("index")
    if not upload_id or index_raw is None:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        index = int(index_raw)
    except (TypeError, ValueError):
        return JsonResponse({"status": "fail"}, status=400)

    try:
        session = UploadSession.objects.get(id=upload_id)
    except (UploadSession.DoesNotExist, ValueError):
        return JsonResponse({"status": "fail"}, status=404)

    is_public = not request.user.is_authenticated
    if session.is_public != is_public:
        return JsonResponse({"status": "fail"}, status=403)
    if session.user_id and request.user.is_authenticated:
        if session.user_id != request.user.id:
            return JsonResponse({"status": "fail"}, status=403)
    if session.user_id and not request.user.is_authenticated:
        return JsonResponse({"status": "fail"}, status=403)

    if index < 0 or index >= session.total_chunks:
        return JsonResponse({"status": "fail"}, status=400)

    if "chunk" not in request.FILES:
        return JsonResponse({"status": "fail"}, status=400)

    uploaded_file = request.FILES["chunk"]

    expected_size = _expected_chunk_size(session, index)
    if expected_size <= 0:
        return JsonResponse({"status": "fail"}, status=400)
    actual_size = _file_size(uploaded_file)
    if actual_size != expected_size:
        return JsonResponse({"status": "fail"}, status=400)

    session_id = str(session.id)
    session_dir = _upload_session_dir(session_id)
    os.makedirs(session_dir, exist_ok=True)

    use_v2 = os.path.exists(_upload_v2_marker_path(session_id))
    if use_v2:
        data_path = _upload_data_path(session_id)
        offset = index * session.chunk_size
        with _open_upload_data_file(data_path) as handle:
            handle.seek(offset)
            try:
                uploaded_file.file.seek(0)
            except Exception:
                pass
            shutil.copyfileobj(uploaded_file.file, handle, length=8 * 1024 * 1024)
        marker_path = _upload_done_marker_path(session_id, index)
        try:
            with open(marker_path, "wb"):
                pass
        except OSError:
            logger.exception("Failed to write upload marker")
    else:
        chunk_path = _upload_chunk_path(session_id, index)
        with open(chunk_path, "wb") as handle:
            try:
                uploaded_file.file.seek(0)
            except Exception:
                pass
            shutil.copyfileobj(uploaded_file.file, handle, length=8 * 1024 * 1024)

    _touch_upload_session(session)

    return JsonResponse({"status": "ok"})


@require_POST
@_private_access
def api_upload_complete(request: HttpRequest) -> JsonResponse:
    data = _parse_json(request)
    upload_id = (data.get("upload_id") or request.POST.get("upload_id") or "").strip()
    if not upload_id:
        return JsonResponse({"status": "fail"}, status=400)

    try:
        session = UploadSession.objects.get(id=upload_id)
    except (UploadSession.DoesNotExist, ValueError):
        return JsonResponse({"status": "fail"}, status=404)

    is_public = not request.user.is_authenticated
    if session.is_public != is_public:
        return JsonResponse({"status": "fail"}, status=403)
    if session.user_id and request.user.is_authenticated:
        if session.user_id != request.user.id:
            return JsonResponse({"status": "fail"}, status=403)
    if session.user_id and not request.user.is_authenticated:
        return JsonResponse({"status": "fail"}, status=403)

    session_id = str(session.id)
    session_dir = _upload_session_dir(session_id)
    os.makedirs(session_dir, exist_ok=True)

    legacy_received = _scan_received_chunk_indices(
        session_id,
        suffix=".part",
        total_chunks=session.total_chunks,
        chunk_size=session.chunk_size,
        total_size=session.total_size,
    )
    received = legacy_received
    scheme = "legacy" if legacy_received else "v2"
    if not legacy_received:
        received = _scan_received_chunk_indices(
            session_id,
            suffix=".done",
            total_chunks=session.total_chunks,
            chunk_size=session.chunk_size,
            total_size=session.total_size,
        )

    received_set = set(received)
    if len(received_set) != session.total_chunks:
        missing = [i for i in range(session.total_chunks) if i not in received_set]
        return JsonResponse({"status": "fail", "missing_chunks": missing}, status=409)

    assembled_path = _upload_data_path(session_id)
    assembled_temp = None
    if scheme == "legacy":
        assembled_temp = os.path.join(session_dir, "assembled.bin")
        try:
            with open(assembled_temp, "wb") as out:
                for index in range(session.total_chunks):
                    chunk_path = _upload_chunk_path(session_id, index)
                    if not os.path.exists(chunk_path):
                        return JsonResponse({"status": "fail"}, status=409)
                    with open(chunk_path, "rb") as chunk_file:
                        shutil.copyfileobj(chunk_file, out, length=8 * 1024 * 1024)
        except OSError:
            logger.exception("Failed to assemble legacy upload chunks")
            return JsonResponse({"status": "fail"}, status=500)
        assembled_path = assembled_temp

    if not os.path.exists(assembled_path):
        return JsonResponse({"status": "fail"}, status=409)
    if os.path.getsize(assembled_path) != session.total_size:
        return JsonResponse({"status": "fail"}, status=409)

    completed = False
    try:
        share = (
            _get_or_create_public_share()
            if is_public
            else _get_or_create_user_share(request.user)
        )
        ttl_seconds = int(
            getattr(
                settings,
                "DSHARE_PUBLIC_TTL_SECONDS" if is_public else "DSHARE_USER_TTL_SECONDS",
                86400 if is_public else 86400 * 30,
            )
        )
        _maybe_expire_share(share=share, ttl_seconds=ttl_seconds)

        if share.file:
            _delete_field_file(share.file)

        stored = False
        try:
            storage = share.file.storage
            final_name = share.file.field.generate_filename(share, session.filename)
            final_path = storage.path(final_name)
            os.makedirs(os.path.dirname(final_path), exist_ok=True)
            os.replace(assembled_path, final_path)
            share.file.name = final_name
            stored = True
        except Exception:
            stored = False

        if not stored:
            with open(assembled_path, "rb") as handle:
                django_file = File(handle, name=session.filename)
                share.file.save(session.filename, django_file, save=False)
        share.text = None
        share.save(update_fields=["file", "text", "updated_at"])
        completed = True
    finally:
        if not completed and assembled_temp and os.path.exists(assembled_temp):
            try:
                os.remove(assembled_temp)
            except OSError:
                logger.exception("Failed to remove assembled temp upload file")
        if completed:
            _delete_upload_session_files(session)
            session.delete()

    return JsonResponse({"status": "ok"})


@require_POST
@_private_access
def upload_view(request: HttpRequest) -> JsonResponse:
    is_public = not request.user.is_authenticated
    if is_public:
        ip = _client_ip(request)
        throttle_key = f"dshare:public_upload:{ip}"
        attempts = cache.get(throttle_key, 0)
        if attempts >= int(getattr(settings, "DSHARE_PUBLIC_UPLOAD_LIMIT", 100)):
            return JsonResponse({"status": "fail"}, status=429)
        cache.set(throttle_key, attempts + 1, timeout=60 * 10)

    max_bytes = int(
        getattr(
            settings,
            "DSHARE_PUBLIC_MAX_UPLOAD_BYTES" if is_public else "DSHARE_USER_MAX_UPLOAD_BYTES",
            10 * 1024 * 1024,
        )
    )
    ttl_seconds = int(
        getattr(
            settings,
            "DSHARE_PUBLIC_TTL_SECONDS" if is_public else "DSHARE_USER_TTL_SECONDS",
            86400 if is_public else 86400 * 30,
        )
    )

    share = _get_or_create_public_share() if is_public else _get_or_create_user_share(request.user)
    _maybe_expire_share(share=share, ttl_seconds=ttl_seconds)

    if "file" in request.FILES:
        uploaded_file = request.FILES["file"]
        if _file_size(uploaded_file) > max_bytes:
            return JsonResponse({"status": "fail"}, status=413)

        if share.file:
            _delete_field_file(share.file)
        share.file = uploaded_file
        share.text = None
        share.save(update_fields=["file", "text", "updated_at"])
        return JsonResponse({"status": "ok"})

    text = request.POST.get("text")
    if text is not None:
        share.text = text
        if share.file:
            _delete_field_file(share.file)
        share.file = None
        share.save(update_fields=["file", "text", "updated_at"])
        return JsonResponse({"status": "ok"})

    return JsonResponse({"status": "fail"}, status=400)


@require_GET
@_private_access
def download_view(request: HttpRequest) -> HttpResponse:
    is_public = not request.user.is_authenticated
    ttl_seconds = int(
        getattr(
            settings,
            "DSHARE_PUBLIC_TTL_SECONDS" if is_public else "DSHARE_USER_TTL_SECONDS",
            86400 if is_public else 86400 * 30,
        )
    )
    share = _get_or_create_public_share() if is_public else _get_or_create_user_share(request.user)
    _maybe_expire_share(share=share, ttl_seconds=ttl_seconds)

    if share.file:
        # Never expose a reusable storage URL for private content.
        return FileResponse(
            share.file.open("rb"), as_attachment=True,
            filename=os.path.basename(share.file.name),
            content_type="application/octet-stream",
        )

    if share.text:
        return HttpResponse(share.text, content_type="text/plain")

    return JsonResponse({"status": "empty"})


@require_GET
@_private_access
def api_share_text(request: HttpRequest) -> JsonResponse:
    is_public = not request.user.is_authenticated
    ttl_seconds = int(
        getattr(
            settings,
            "DSHARE_PUBLIC_TTL_SECONDS" if is_public else "DSHARE_USER_TTL_SECONDS",
            86400 if is_public else 86400 * 30,
        )
    )
    share = _get_or_create_public_share() if is_public else _get_or_create_user_share(request.user)
    _maybe_expire_share(share=share, ttl_seconds=ttl_seconds)
    return JsonResponse({"text": share.text or ""})


@require_POST
@_private_access
def api_share_clear(request: HttpRequest) -> JsonResponse:
    is_public = not request.user.is_authenticated
    if is_public:
        ip = _client_ip(request)
        throttle_key = f"dshare:public_clear:{ip}"
        attempts = cache.get(throttle_key, 0)
        if attempts >= int(getattr(settings, "DSHARE_PUBLIC_CLEAR_LIMIT", 100)):
            return JsonResponse({"status": "fail"}, status=429)
        cache.set(throttle_key, attempts + 1, timeout=60 * 10)

    share = _get_or_create_public_share() if is_public else _get_or_create_user_share(request.user)
    if share.file:
        _delete_field_file(share.file)
    share.file = None
    share.text = None
    share.save(update_fields=["file", "text", "updated_at"])
    return JsonResponse({"status": "ok"})
