"""Bounded transfer admission and durable, disk-free object-storage uploads."""
import fcntl
import logging
import os
import tempfile
from functools import wraps

from botocore.exceptions import ClientError
from django.conf import settings
from django.core.files.storage import default_storage
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from storages.backends.s3 import S3Storage

from .models import UploadSession

logger = logging.getLogger(__name__)


def multipart_storage():
    return default_storage if isinstance(default_storage, S3Storage) else None


def object_key(storage, name):
    return storage._normalize_name(name)


def transfer_priority(view):
    """Public transfers share four slots across workers; private bypasses them."""
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if request.user.is_authenticated or request.method == "HEAD":
            return view(request, *args, **kwargs)
        root = getattr(settings, "DSHARE_TRANSFER_SLOT_DIR", os.path.join(tempfile.gettempdir(), "dshare_transfer_slots"))
        os.makedirs(root, exist_ok=True)
        lock = None
        for slot in range(int(getattr(settings, "DSHARE_PUBLIC_TRANSFER_SLOTS", 4))):
            candidate = open(os.path.join(root, f"public-{slot}.lock"), "a+b")
            try:
                fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock = candidate
                break
            except BlockingIOError:
                candidate.close()
        if lock is None:
            if request.path == "/download/" and "text/html" in request.headers.get("Accept", ""):
                response = HttpResponse('<!doctype html><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="2"><title>Starting download</title><body style="background:#111;color:#fff;font-family:system-ui;padding:3rem">Your download will start shortly… <a href="/" style="color:#bbb">Back to dshare</a></body>', status=429)
            else:
                response = JsonResponse({"status": "busy", "code": "public_transfer_busy", "message": "Public transfers are busy. Retry shortly."}, status=429)
            response["Retry-After"] = "2"
            return response
        try:
            response = view(request, *args, **kwargs)
        except BaseException:
            lock.close()
            raise
        if response.streaming:
            response._resource_closers.append(lock.close)
        else:
            lock.close()
        return response
    return wrapped


def begin_multipart(session, share):
    storage = multipart_storage()
    name = share.file.field.generate_filename(share, f"{session.id}/{os.path.basename(session.filename)}")
    name = storage.get_available_name(name, max_length=share.file.field.max_length)
    result = storage.connection.meta.client.create_multipart_upload(
        Bucket=storage.bucket_name, Key=object_key(storage, name),
        ContentType=session.content_type or "application/octet-stream",
        Metadata={"dshare-session": str(session.id)},
    )
    session.storage_key = name
    session.storage_upload_id = result["UploadId"]
    try:
        session.save(update_fields=["storage_key", "storage_upload_id", "updated_at"])
    except Exception:
        storage.connection.meta.client.abort_multipart_upload(
            Bucket=storage.bucket_name, Key=object_key(storage, name), UploadId=result["UploadId"])
        raise


def store_multipart_chunk(session, index, uploaded_file):
    # A lost HTTP response must not overwrite an already confirmed R2 part.
    if str(index) in session.part_etags:
        return
    storage = multipart_storage()
    uploaded_file.seek(0)
    result = storage.connection.meta.client.upload_part(
        Bucket=storage.bucket_name, Key=object_key(storage, session.storage_key),
        UploadId=session.storage_upload_id, PartNumber=index + 1,
        Body=uploaded_file.file, ContentLength=uploaded_file.size,
    )
    # Merge receipts under a short DB lock, never hold it during network IO.
    with transaction.atomic():
        current = UploadSession.objects.select_for_update().get(id=session.id)
        if current.completed_at:
            return
        receipts = dict(current.part_etags)
        receipts[str(index)] = result["ETag"]
        current.part_etags = receipts
        current.save(update_fields=["part_etags", "updated_at"])


def reconcile_multipart_receipts(session, storage):
    """Recover actual storage state after an interrupted/retried part upload."""
    client = storage.connection.meta.client
    params = {"Bucket": storage.bucket_name, "Key": object_key(storage, session.storage_key),
        "UploadId": session.storage_upload_id}
    actual = {}
    while True:
        page = client.list_parts(**params)
        for part in page.get("Parts", []):
            index = part["PartNumber"] - 1
            expected = min(session.chunk_size, session.total_size - index * session.chunk_size)
            if 0 <= index < session.total_chunks and part["Size"] == expected:
                actual[str(index)] = part["ETag"]
        if not page.get("IsTruncated"):
            break
        params["PartNumberMarker"] = page["NextPartNumberMarker"]
    with transaction.atomic():
        current = UploadSession.objects.select_for_update().get(id=session.id)
        receipts = dict(current.part_etags)
        for index, etag in session.part_etags.items():
            if receipts.get(index) == etag:
                if index in actual:
                    receipts[index] = actual[index]
                else:
                    receipts.pop(index, None)
        for index, etag in actual.items():
            receipts.setdefault(index, etag)
        current.part_etags = receipts
        current.save(update_fields=["part_etags", "updated_at"])
        session.part_etags = receipts


def finish_multipart(session, share):
    storage = multipart_storage()
    missing = [i for i in range(session.total_chunks) if str(i) not in session.part_etags]
    if missing:
        return JsonResponse({"status": "fail", "missing_chunks": missing}, status=409)
    key = object_key(storage, session.storage_key)
    client = storage.connection.meta.client
    try:
        client.complete_multipart_upload(
            Bucket=storage.bucket_name, Key=key, UploadId=session.storage_upload_id,
            MultipartUpload={"Parts": [{"PartNumber": i + 1, "ETag": session.part_etags[str(i)]} for i in range(session.total_chunks)]},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("InvalidPart", "InvalidPartOrder"):
            reconcile_multipart_receipts(session, storage)
            missing = [i for i in range(session.total_chunks) if str(i) not in session.part_etags]
            return JsonResponse({"status": "fail", "missing_chunks": missing}, status=409) if missing else JsonResponse({"status": "fail", "code": "retry_completion"}, status=503)
        if exc.response["Error"]["Code"] != "NoSuchUpload":
            raise
        # Recover if storage committed successfully before a response/DB failure.
        result = client.head_object(Bucket=storage.bucket_name, Key=key)
        if result["ContentLength"] != session.total_size or result.get("Metadata", {}).get("dshare-session") != str(session.id):
            raise
    old_name = share.file.name if share.file else None
    share.file.name = session.storage_key
    share.text = None
    with transaction.atomic():
        share.save(update_fields=["file", "text", "updated_at"])
        session.completed_at = timezone.now()
        session.save(update_fields=["completed_at", "updated_at"])
    if old_name and old_name != session.storage_key:
        try:
            storage.delete(old_name)
        except Exception:
            logger.exception("Failed to delete replaced object")
    return JsonResponse({"status": "ok"})


def abort_expired_multipart(session):
    if not session.storage_upload_id or session.completed_at:
        return
    storage = multipart_storage()
    if storage is None:
        return
    try:
        storage.connection.meta.client.abort_multipart_upload(
            Bucket=storage.bucket_name, Key=object_key(storage, session.storage_key),
            UploadId=session.storage_upload_id,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchUpload":
            raise


def parallel_object_chunks(client, bucket, key, start, length, etag, concurrency, part_size=4 * 1024 * 1024):
    """Prefetch a small bounded window of ranges, preserving byte order."""
    from collections import deque
    from concurrent.futures import ThreadPoolExecutor


    def read_range(offset, count):
        result = client.get_object(Bucket=bucket, Key=key,
            Range=f"bytes={offset}-{offset+count-1}", IfMatch=etag)
        body = result["Body"]
        try:
            data = body.read(count)
            if len(data) != count:
                raise OSError("Storage returned a truncated download range")
            return data
        finally:
            body.close()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        pending = deque()
        offset, end = start, start + length
        while offset < end or pending:
            while offset < end and len(pending) < concurrency:
                count = min(part_size, end - offset)
                pending.append(executor.submit(read_range, offset, count))
                offset += count
            data = pending.popleft().result()
            # Continue emitting small blocks to the browser/socket.
            for i in range(0, len(data), 1024 * 1024):
                yield data[i:i + 1024 * 1024]
