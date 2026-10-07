import json
import tempfile

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from .models import EmailVerificationToken, PublicShareState, UserProfile, UserShareState

User = get_user_model()


class ShareFlowsTests(TestCase):
    def test_public_upload_and_download_text(self):
        res = self.client.post(reverse("upload"), {"text": "hello"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

        public_share = PublicShareState.objects.get(pk=1)
        self.assertEqual(public_share.text, "hello")

        download = self.client.get(reverse("download"))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download["Content-Type"], "text/plain")
        self.assertEqual(download.content.decode("utf-8"), "hello")

    def test_user_upload_is_private(self):
        user = User.objects.create_user(username="u@example.com", email="u@example.com", password="pw")
        UserProfile.objects.create(user=user, email_verified_at=timezone.now())
        self.client.force_login(user)

        res = self.client.post(reverse("upload"), {"text": "secret"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

        user_share = UserShareState.objects.get(user=user)
        self.assertEqual(user_share.text, "secret")

        self.assertFalse(PublicShareState.objects.exists())

        download = self.client.get(reverse("download"))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content.decode("utf-8"), "secret")

        self.client.logout()
        public_download = self.client.get(reverse("download"))
        self.assertEqual(public_download.status_code, 200)
        self.assertEqual(public_download.json()["status"], "empty")

    def test_upload_requires_csrf_and_home_sets_cookie(self):
        client = Client(enforce_csrf_checks=True)
        home = client.get(reverse("home"))
        self.assertEqual(home.status_code, 200)
        self.assertIn("csrftoken", home.cookies)

        token = home.cookies["csrftoken"].value
        res = client.post(
            reverse("upload"),
            {"text": "hello"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")


class ChunkedUploadTests(TestCase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _storage_settings(self):
        return {
            "MEDIA_ROOT": self._tmp.name,
            "MEDIA_URL": "/media/",
            "STORAGES": {
                "default": {
                    "BACKEND": "django.core.files.storage.FileSystemStorage",
                    "OPTIONS": {"location": self._tmp.name, "base_url": "/media/"},
                },
                "staticfiles": {
                    "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
                },
            },
            "DSHARE_UPLOAD_MIN_CHUNK_BYTES": 1,
            "DSHARE_UPLOAD_MAX_CHUNK_BYTES": 1024 * 1024,
        }

    def test_chunked_upload_scans_disk_for_resume_and_completes(self):
        content = b"abcdefghijklmnopqrstuvwxyz"
        chunk_size = 10

        with override_settings(**self._storage_settings()):
            start = self.client.post(
                reverse("api_upload_start"),
                data=json.dumps(
                    {
                        "filename": "test.bin",
                        "size": len(content),
                        "chunk_size": chunk_size,
                        "content_type": "application/octet-stream",
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(start.status_code, 200)
            start_data = start.json()
            self.assertEqual(start_data["status"], "ok")
            upload_id = start_data["upload_id"]
            self.assertEqual(start_data["chunk_size"], chunk_size)
            self.assertEqual(start_data["total_chunks"], 3)
            self.assertEqual(start_data["received_chunks"], [])

            # Upload out of order (v2 writes to a single file at offsets).
            for index in (2, 0):
                offset = index * chunk_size
                part = content[offset : offset + chunk_size]
                if index == 2:
                    self.assertEqual(len(part), 6)
                res = self.client.post(
                    reverse("api_upload_chunk"),
                    data={
                        "upload_id": upload_id,
                        "index": str(index),
                        "chunk": SimpleUploadedFile(
                            "test.bin", part, content_type="application/octet-stream"
                        ),
                    },
                )
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.json()["status"], "ok")

            # Start again (resume) should scan disk markers and report received chunks.
            resume = self.client.post(
                reverse("api_upload_start"),
                data=json.dumps(
                    {
                        "filename": "test.bin",
                        "size": len(content),
                        "chunk_size": chunk_size,
                        "content_type": "application/octet-stream",
                        "upload_id": upload_id,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resume.status_code, 200)
            resume_data = resume.json()
            self.assertEqual(resume_data["status"], "ok")
            self.assertEqual(resume_data["upload_id"], upload_id)
            self.assertEqual(resume_data["received_chunks"], [0, 2])

            # Upload the missing middle chunk.
            index = 1
            offset = index * chunk_size
            part = content[offset : offset + chunk_size]
            self.assertEqual(len(part), 10)
            res = self.client.post(
                reverse("api_upload_chunk"),
                data={
                    "upload_id": upload_id,
                    "index": str(index),
                    "chunk": SimpleUploadedFile(
                        "test.bin", part, content_type="application/octet-stream"
                    ),
                },
            )
            self.assertEqual(res.status_code, 200)

            complete = self.client.post(
                reverse("api_upload_complete"),
                data=json.dumps({"upload_id": upload_id}),
                content_type="application/json",
            )
            self.assertEqual(complete.status_code, 200)
            self.assertEqual(complete.json()["status"], "ok")

            share = PublicShareState.objects.get(pk=1)
            self.assertIsNotNone(share.file)
            with share.file.open("rb") as handle:
                self.assertEqual(handle.read(), content)

    def test_chunked_upload_complete_reports_missing_chunks(self):
        content = b"abcdefghijklmnopqrstuvwxyz"
        chunk_size = 10

        with override_settings(**self._storage_settings()):
            start = self.client.post(
                reverse("api_upload_start"),
                data=json.dumps(
                    {
                        "filename": "test.bin",
                        "size": len(content),
                        "chunk_size": chunk_size,
                        "content_type": "application/octet-stream",
                    }
                ),
                content_type="application/json",
            )
            upload_id = start.json()["upload_id"]

            # Upload only the first chunk.
            part0 = content[:chunk_size]
            res = self.client.post(
                reverse("api_upload_chunk"),
                data={
                    "upload_id": upload_id,
                    "index": "0",
                    "chunk": SimpleUploadedFile(
                        "test.bin", part0, content_type="application/octet-stream"
                    ),
                },
            )
            self.assertEqual(res.status_code, 200)

            complete = self.client.post(
                reverse("api_upload_complete"),
                data=json.dumps({"upload_id": upload_id}),
                content_type="application/json",
            )
            self.assertEqual(complete.status_code, 409)
            data = complete.json()
            self.assertEqual(data["status"], "fail")
            self.assertEqual(data["missing_chunks"], [1, 2])


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class AuthFlowsTests(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()

    def test_register_requires_password(self):
        res = self.client.post(
            reverse("api_auth_register"),
            data=json.dumps({"email": "a@example.com", "password": ""}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["status"], "fail")

    def test_register_sets_password_and_optional_pin_after_verify(self):
        res = self.client.post(
            reverse("api_auth_register"),
            data=json.dumps({"email": "p@example.com", "password": "pw12345", "pin": "1234"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")
        self.assertEqual(len(mail.outbox), 1)

        user = User.objects.get(username="p@example.com")
        self.assertFalse(user.has_usable_password())
        token = EmailVerificationToken.objects.get(user=user)

        verify = self.client.get(
            reverse("auth_verify_email", kwargs={"token": token.token})
        )
        self.assertEqual(verify.status_code, 302)

        user.refresh_from_db()
        self.assertTrue(user.has_usable_password())
        self.assertTrue(user.check_password("pw12345"))
        profile = UserProfile.objects.get(user=user)
        self.assertTrue(check_password("1234", profile.pin_hash))

        self.client.post(reverse("api_auth_logout"))
        login_res = self.client.post(
            reverse("api_auth_login"),
            data=json.dumps({"email": "p@example.com", "secret": "pw12345"}),
            content_type="application/json",
        )
        self.assertEqual(login_res.status_code, 200)
        self.assertEqual(login_res.json()["status"], "ok")

        self.client.post(reverse("api_auth_logout"))
        pin_login = self.client.post(
            reverse("api_auth_login"),
            data=json.dumps({"email": "p@example.com", "secret": "1234"}),
            content_type="application/json",
        )
        self.assertEqual(pin_login.status_code, 200)
        self.assertEqual(pin_login.json()["status"], "ok")

    def test_register_sets_password_even_if_verified_elsewhere(self):
        client_a = Client()
        client_b = Client()

        res = client_a.post(
            reverse("api_auth_register"),
            data=json.dumps({"email": "x@example.com", "password": "pw99999", "pin": "9999"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)

        user = User.objects.get(username="x@example.com")
        token = EmailVerificationToken.objects.get(user=user)

        verify = client_b.get(
            reverse("auth_verify_email", kwargs={"token": token.token})
        )
        self.assertEqual(verify.status_code, 302)

        user.refresh_from_db()
        self.assertTrue(user.has_usable_password())
        self.assertTrue(user.check_password("pw99999"))

        profile = UserProfile.objects.get(user=user)
        self.assertIsNotNone(profile.email_verified_at)
        self.assertTrue(check_password("9999", profile.pin_hash))

        login_res = client_a.post(
            reverse("api_auth_login"),
            data=json.dumps({"email": "x@example.com", "secret": "pw99999"}),
            content_type="application/json",
        )
        self.assertEqual(login_res.status_code, 200)
        self.assertEqual(login_res.json()["status"], "ok")

    def test_password_login_requires_verified_email(self):
        user = User.objects.create_user(
            username="u@example.com", email="u@example.com", password="pw"
        )
        UserProfile.objects.get_or_create(user=user)

        res = self.client.post(
            reverse("api_auth_login"),
            data=json.dumps({"email": "u@example.com", "secret": "pw"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()["status"], "fail")

    def test_email_status_can_login_only_when_verified(self):
        res = self.client.post(
            reverse("api_auth_email_status"),
            data=json.dumps({"email": "new@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")
        self.assertFalse(res.json()["can_login"])

        unverified = User.objects.create_user(
            username="u2@example.com", email="u2@example.com", password="pw"
        )
        UserProfile.objects.get_or_create(user=unverified)
        res2 = self.client.post(
            reverse("api_auth_email_status"),
            data=json.dumps({"email": "u2@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 200)
        self.assertFalse(res2.json()["can_login"])

        verified = User.objects.create_user(
            username="v@example.com", email="v@example.com", password="pw"
        )
        UserProfile.objects.update_or_create(
            user=verified,
            defaults={"email_verified_at": timezone.now()},
        )
        res3 = self.client.post(
            reverse("api_auth_email_status"),
            data=json.dumps({"email": "v@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(res3.status_code, 200)
        self.assertTrue(res3.json()["can_login"])

    def test_verify_email_rejects_expired_token(self):
        user = User.objects.create_user(username="z@example.com", email="z@example.com", password="pw")
        token = EmailVerificationToken.objects.create(user=user)
        EmailVerificationToken.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=2)
        )
        token.refresh_from_db()

        res = self.client.get(reverse("auth_verify_email", kwargs={"token": token.token}))
        self.assertEqual(res.status_code, 302)
        self.assertFalse(UserProfile.objects.filter(user=user, email_verified_at__isnull=False).exists())


class PrivateAccessTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner@example.com", password="pw")
        self.other = User.objects.create_user(username="other@example.com", password="pw")
        for user in (self.owner, self.other):
            UserProfile.objects.create(user=user, email_verified_at=timezone.now())

    def test_unverified_session_cannot_read_or_modify_private_data(self):
        UserProfile.objects.filter(user=self.owner).update(email_verified_at=None)
        UserShareState.objects.create(user=self.owner, text="secret")
        self.client.force_login(self.owner)
        for name in ("download", "api_share_text"):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 403)
            self.assertIn("no-store", response["Cache-Control"])
        for name in ("upload", "api_share_clear", "api_upload_start", "api_upload_chunk", "api_upload_complete"):
            self.assertEqual(self.client.post(reverse(name)).status_code, 403)
        self.assertEqual(UserShareState.objects.get(user=self.owner).text, "secret")

    def test_other_account_and_anonymous_cannot_read_owner_text(self):
        UserShareState.objects.create(user=self.owner, text="secret")
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(reverse("api_share_text")).json()["text"], "")
        self.client.logout()
        self.assertEqual(self.client.get(reverse("api_share_text")).json()["text"], "")

    def test_private_file_streamed_without_storage_url_and_direct_media_denied(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(MEDIA_ROOT=directory):
            share = UserShareState.objects.create(user=self.owner)
            share.file.save("private.txt", SimpleUploadedFile("private.txt", b"private bytes"))
            self.client.force_login(self.owner)
            response = self.client.get(reverse("download"))
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("Location", response)
            self.assertIn("attachment", response["Content-Disposition"])
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(b"".join(response.streaming_content), b"private bytes")
            response.close()
            for client in (self.client, Client()):
                self.assertEqual(client.get(share.file.url).status_code, 404)

    def test_other_account_cannot_complete_private_upload(self):
        from .models import UploadSession
        session = UploadSession.objects.create(
            user=self.owner, is_public=False, filename="secret.txt",
            total_size=4, chunk_size=4, total_chunks=1,
        )
        for client in (self.client, Client()):
            if client is self.client:
                client.force_login(self.other)
            response = client.post(
                reverse("api_upload_complete"),
                data=json.dumps({"upload_id": str(session.id)}),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 403)
        self.assertTrue(UploadSession.objects.filter(pk=session.pk).exists())

    def test_passkey_authentication_requires_user_verification(self):
        response = self.client.post(reverse("api_webauthn_auth_begin"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["publicKey"]["userVerification"], "required")
