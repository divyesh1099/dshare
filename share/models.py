import secrets
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    email_verified_at = models.DateTimeField(null=True, blank=True)
    pin_hash = models.CharField(max_length=128, null=True, blank=True)
    webauthn_user_id = models.BinaryField(null=True, blank=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def ensure_webauthn_user_id(self) -> bytes:
        if self.webauthn_user_id:
            return bytes(self.webauthn_user_id)

        self.webauthn_user_id = secrets.token_bytes(32)
        self.save(update_fields=["webauthn_user_id"])
        return bytes(self.webauthn_user_id)


def _email_token_default() -> str:
    return secrets.token_urlsafe(32)


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_verification_tokens",
    )
    token = models.CharField(max_length=128, unique=True, default=_email_token_default)
    pending_password_hash = models.CharField(max_length=128, null=True, blank=True)
    pending_pin_hash = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    def is_expired(self, *, max_age_seconds: int) -> bool:
        if max_age_seconds <= 0:
            return True
        return self.created_at < timezone.now() - timezone.timedelta(seconds=max_age_seconds)


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="webauthn_credentials",
    )
    credential_id = models.BinaryField(unique=True)
    credential_data = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class UserShareState(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="share_state"
    )
    file = models.FileField(upload_to="uploads/user/", null=True, blank=True)
    text = models.TextField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class PublicShareState(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    file = models.FileField(upload_to="uploads/public/", null=True, blank=True)
    text = models.TextField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class UploadSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="upload_sessions",
        null=True,
        blank=True,
    )
    is_public = models.BooleanField(default=True)
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=255, blank=True)
    total_size = models.BigIntegerField()
    chunk_size = models.PositiveIntegerField()
    total_chunks = models.PositiveIntegerField()
    received_chunks = models.JSONField(default=list, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    storage_upload_id = models.CharField(max_length=1024, blank=True)
    storage_key = models.CharField(max_length=1024, blank=True)
    part_etags = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
