import json
import tempfile
from unittest.mock import MagicMock

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

    def test_object_storage_download_streams_in_bounded_reads(self):
        from .views import _private_file_response

        body = MagicMock()
        body.read.side_effect = [b"first", b"second", b""]
        client = MagicMock()
        client.get_object.return_value = {
            "Body": body,
            "ContentLength": 11,
            "ContentType": "text/plain",
        }
        storage = MagicMock()
        storage.bucket_name = "private-bucket"
        storage.connection.meta.client = client
        field_file = MagicMock()
        field_file.storage = storage
        field_file.name = "uploads/user/private.txt"

        response = _private_file_response(field_file)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Length"], "11")
        self.assertEqual(b"".join(response.streaming_content), b"firstsecond")
        self.assertEqual(body.read.call_count, 2)
        self.assertTrue(all(call.args[0] <= 1024 * 1024 for call in body.read.call_args_list))
        body.close.assert_called_once()
        field_file.open.assert_not_called()


class LargeTransferTests(ChunkedUploadTests):
    def test_700_mib_roundtrip_public_and_private(self):
        import hashlib
        from .models import UploadSession

        user = User.objects.create_user(username="large", password="pw")
        UserProfile.objects.create(user=user, email_verified_at=timezone.now())
        total = 700 * 1024 * 1024
        chunk_size = 8 * 1024 * 1024
        storage_settings = self._storage_settings()
        storage_settings["DSHARE_UPLOAD_MAX_CHUNK_BYTES"] = chunk_size
        with override_settings(**storage_settings):
            for private in (False, True):
                if private:
                    self.client.force_login(user)
                start = self.client.post(reverse("api_upload_start"),
                    data=json.dumps({"filename": "large.bin", "size": total, "chunk_size": chunk_size}),
                    content_type="application/json")
                self.assertEqual(start.status_code, 200)
                session_id = start.json()["upload_id"]
                digest = hashlib.sha256()
                for index in range(start.json()["total_chunks"]):
                    # Different bytes in each chunk detect offset/assembly errors.
                    part = bytes([index % 256]) * min(chunk_size, total - index * chunk_size)
                    digest.update(part)
                    response = self.client.post(reverse("api_upload_chunk"), {
                        "upload_id": session_id, "index": index,
                        "chunk": SimpleUploadedFile("large.bin", part)})
                    self.assertEqual(response.status_code, 200)
                payload = json.dumps({"upload_id": session_id})
                for _ in range(2):  # Lost completion response can safely be retried.
                    response = self.client.post(reverse("api_upload_complete"), data=payload, content_type="application/json")
                    self.assertEqual(response.status_code, 200)
                self.assertIsNotNone(UploadSession.objects.get(id=session_id).completed_at)
                response = self.client.get(reverse("download"))
                actual = hashlib.sha256()
                size = 0
                for block in response.streaming_content:
                    self.assertLessEqual(len(block), 1024 * 1024)
                    actual.update(block)
                    size += len(block)
                response.close()
                self.assertEqual(size, total)
                self.assertEqual(actual.digest(), digest.digest())
                resumed = self.client.get(reverse("download"), HTTP_RANGE=f"bytes={total-1024}-")
                self.assertEqual(resumed.status_code, 206)
                self.assertEqual(len(b"".join(resumed.streaming_content)), 1024)
                resumed.close()
                head = self.client.head(reverse("download"))
                self.assertEqual(head.status_code, 200)
                self.assertEqual(int(head["Content-Length"]), total)
                invalid = self.client.get(reverse("download"), HTTP_RANGE=f"bytes={total}-")
                self.assertEqual(invalid.status_code, 416)
                share = UserShareState.objects.get(user=user) if private else PublicShareState.objects.get(pk=1)
                share.file.delete()

    def test_s3_range_forwarded_without_buffering(self):
        from django.test import RequestFactory
        from .views import _private_file_response
        body = MagicMock()
        body.read.return_value = b"tail"
        field = MagicMock()
        field.name = "uploads/user/example.bin"
        field.size = 700 * 1024 * 1024
        field.storage.bucket_name = "private"
        client = field.storage.connection.meta.client
        client.get_object.return_value = {"Body": body, "ContentLength": 4}
        response = _private_file_response(field, RequestFactory().get("/download/", HTTP_RANGE="bytes=-4"))
        self.assertEqual(response.status_code, 206)
        self.assertEqual(b"".join(response.streaming_content), b"tail")
        client.get_object.assert_called_once_with(Bucket="private", Key=field.name,
            Range=f"bytes={field.size-4}-{field.size-1}")
        field.open.assert_not_called()


class MultipartTransferTests(TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.override = override_settings(MEDIA_ROOT=self.tmp.name,
            DSHARE_TRANSFER_SLOT_DIR=self.tmp.name + '/slots', DSHARE_PUBLIC_TRANSFER_SLOTS=2,
            STORAGES={'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
                'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'}})
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.storage = MagicMock()
        self.storage.bucket_name = 'test'
        self.storage._normalize_name.side_effect = lambda name: name
        self.storage.get_available_name.side_effect = lambda name, max_length: name
        self.sdk = self.storage.connection.meta.client
        self.sdk.create_multipart_upload.return_value = {'UploadId': 'multipart-id'}
        self.parts = {}
        def upload_part(**kwargs):
            self.parts[kwargs['PartNumber']] = kwargs['Body'].read()
            return {'ETag': 'part-' + str(kwargs['PartNumber'])}
        self.sdk.upload_part.side_effect = upload_part
        for target in ('share.views.multipart_storage', 'share.transfers.multipart_storage'):
            patcher = patch(target, return_value=self.storage)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.user = User.objects.create_user(username='multipart', password='pw')
        UserProfile.objects.create(user=self.user, email_verified_at=timezone.now())

    def start(self, size):
        return self.client.post(reverse('api_upload_start'),
            data=json.dumps({'filename': 'file.bin', 'size': size, 'chunk_size': 8*1024*1024}),
            content_type='application/json')

    def test_private_10_gib_limit_and_public_limit(self):
        self.client.force_login(self.user)
        response = self.start(10*1024**3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['total_chunks'], 1280)
        self.assertEqual(response.json()['parallel_chunks'], 6)
        self.assertEqual(self.start(10*1024**3 + 1).status_code, 413)
        self.client.logout()
        self.assertEqual(self.start(700*1024**2).status_code, 200)
        self.assertEqual(self.start(1024**3 + 1).status_code, 413)

    def test_multipart_public_private_resume_complete_without_disk_staging(self):
        import os
        from unittest.mock import patch
        from .models import UploadSession
        from .views import _upload_session_dir
        for private in (False, True):
            if private:
                self.client.force_login(self.user)
            content = b'a' * (8*1024*1024) + b'b' * 1024
            start = self.start(len(content)).json()
            session_id = start['upload_id']
            for index, part in ((1, content[8*1024*1024:]), (0, content[:8*1024*1024])):
                response = self.client.post(reverse('api_upload_chunk'), {
                    'upload_id': session_id, 'index': index,
                    'chunk': SimpleUploadedFile('file.bin', part)})
                self.assertEqual(response.status_code, 200)
            resume = self.client.post(reverse('api_upload_start'),
                data=json.dumps({'filename': 'file.bin', 'size': len(content),
                    'chunk_size': start['chunk_size'], 'upload_id': session_id}),
                content_type='application/json').json()
            self.assertEqual(resume['received_chunks'], [0, 1])
            self.assertEqual(resume['upload_id'], session_id)
            self.assertFalse(os.path.exists(_upload_session_dir(session_id)))
            self.assertEqual(self.parts[1] + self.parts[2], content)
            for _ in range(2):
                response = self.client.post(reverse('api_upload_complete'),
                    data=json.dumps({'upload_id': session_id}), content_type='application/json')
                self.assertEqual(response.status_code, 200)
            self.assertIsNotNone(UploadSession.objects.get(id=session_id).completed_at)
            call = self.sdk.complete_multipart_upload.call_args.kwargs
            self.assertEqual(call['MultipartUpload']['Parts'], [
                {'PartNumber': 1, 'ETag': 'part-1'}, {'PartNumber': 2, 'ETag': 'part-2'}])
            share = UserShareState.objects.get(user=self.user) if private else PublicShareState.objects.get(pk=1)
            self.assertIn(session_id, share.file.name)
            self.assertFalse(os.path.exists(_upload_session_dir(session_id)))

    def test_completion_recovers_after_storage_commit_and_response_loss(self):
        from botocore.exceptions import ClientError
        from .models import UploadSession
        from .transfers import finish_multipart
        session = UploadSession.objects.create(user=self.user, is_public=False,
            filename='file.bin', total_size=7, chunk_size=8*1024*1024, total_chunks=1,
            storage_upload_id='old-id', storage_key='unique/file.bin', part_etags={'0': 'etag'})
        self.sdk.complete_multipart_upload.side_effect = ClientError({'Error': {'Code': 'NoSuchUpload'}}, 'CompleteMultipartUpload')
        self.sdk.head_object.return_value = {'ContentLength': 7, 'Metadata': {'dshare-session': str(session.id)}}
        share = UserShareState.objects.create(user=self.user)
        response = finish_multipart(session, share)
        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertIsNotNone(session.completed_at)

    def test_public_slots_are_shared_and_private_bypasses_saturation(self):
        from django.test import RequestFactory
        from django.http import StreamingHttpResponse
        from django.contrib.auth.models import AnonymousUser
        from .transfers import transfer_priority
        factory = RequestFactory()
        @transfer_priority
        def view(request):
            return StreamingHttpResponse(iter([b'x']))
        request = factory.get('/download/')
        request.user = AnonymousUser()
        first, second = view(request), view(request)
        try:
            busy = view(request)
            self.assertEqual(busy.status_code, 429)
            self.assertEqual(busy['Retry-After'], '2')
            request.user = self.user
            private = view(request)
            self.assertEqual(private.status_code, 200)
            private.close()
        finally:
            first.close()
            second.close()
        request.user = AnonymousUser()
        available = view(request)
        self.assertEqual(available.status_code, 200)
        available.close()

    def test_parallel_download_preserves_order_with_bounded_reads(self):
        import io, time
        from .transfers import parallel_object_chunks
        data = b'a'*(2*1024*1024) + b'b'*(2*1024*1024) + b'c'*123
        def get_object(**kwargs):
            first, last = map(int, kwargs['Range'][6:].split('-'))
            if first == 0:
                time.sleep(.02)  # Later ranges complete first.
            self.assertEqual(kwargs['IfMatch'], 'immutable-etag')
            return {'Body': io.BytesIO(data[first:last+1])}
        self.sdk.get_object.side_effect = get_object
        chunks = list(parallel_object_chunks(self.sdk, 'test', 'key', 0, len(data), 'immutable-etag', 3, part_size=2*1024*1024))
        self.assertEqual(b''.join(chunks), data)
        self.assertTrue(all(len(chunk) <= 1024*1024 for chunk in chunks))
        self.assertEqual(self.sdk.get_object.call_count, 3)

    def test_failed_completion_preserves_existing_share_and_receipts(self):
        from botocore.exceptions import ClientError
        from .models import UploadSession
        self.client.force_login(self.user)
        share = UserShareState.objects.create(user=self.user, file='uploads/user/previous.bin')
        session = UploadSession.objects.create(user=self.user, is_public=False,
            filename='file.bin', total_size=7, chunk_size=8*1024*1024, total_chunks=1,
            storage_upload_id='id', storage_key='unique/file.bin', part_etags={'0': 'etag'})
        self.sdk.complete_multipart_upload.side_effect = ClientError({'Error': {'Code': 'InternalError'}}, 'CompleteMultipartUpload')
        response = self.client.post(reverse('api_upload_complete'),
            data=json.dumps({'upload_id': str(session.id)}), content_type='application/json')
        self.assertEqual(response.status_code, 503)
        share.refresh_from_db()
        session.refresh_from_db()
        self.assertEqual(share.file.name, 'uploads/user/previous.bin')
        self.assertIsNone(session.completed_at)
        self.assertEqual(session.part_etags, {'0': 'etag'})

    def test_large_s3_download_route_uses_parallel_ranges_and_preserves_bytes(self):
        import io, hashlib
        from django.test import RequestFactory
        from .views import _private_file_response
        field = MagicMock()
        field.name = 'uploads/user/large.bin'
        field.storage = self.storage
        field.size = 64*1024*1024
        first_body = MagicMock()
        def get_object(**kwargs):
            if 'Range' not in kwargs:
                return {'Body': first_body, 'ContentLength': field.size, 'ETag': 'fixed'}
            start, end = map(int, kwargs['Range'][6:].split('-'))
            return {'Body': io.BytesIO(b'x'*(end-start+1))}
        self.sdk.get_object.side_effect = get_object
        request = RequestFactory().get('/download/')
        request.user = self.user
        response = _private_file_response(field, request)
        digest = hashlib.sha256()
        size = 0
        for chunk in response.streaming_content:
            self.assertLessEqual(len(chunk), 1024*1024)
            size += len(chunk)
            digest.update(chunk)
        response.close()
        self.assertEqual(size, field.size)
        self.assertEqual(digest.digest(), hashlib.sha256(b'x'*field.size).digest())
        first_body.read.assert_not_called()
        field.open.assert_not_called()
        self.assertEqual(self.sdk.get_object.call_count, 17)


class ProductionStorageConfigTests(TestCase):
    def test_exact_production_options_initialize_installed_storage_backend(self):
        import os, subprocess, sys
        env = dict(os.environ, AWS_ACCESS_KEY_ID="test-key", AWS_SECRET_ACCESS_KEY="test-secret",
            AWS_STORAGE_BUCKET_NAME="test-bucket", AWS_S3_ENDPOINT_URL="https://example.invalid",
            DJANGO_SETTINGS_MODULE="dshare.settings")
        result = subprocess.run([sys.executable, "-c", "import django; django.setup(); from django.core.files.storage import default_storage; from storages.backends.s3 import S3Storage; assert isinstance(default_storage, S3Storage); assert default_storage.bucket_name == 'test-bucket'; assert default_storage.config.s3['addressing_style'] == 'path'"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
