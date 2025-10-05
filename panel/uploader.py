# uploader.py
import json
from contextlib import contextmanager
import json
from contextlib import contextmanager
from typing import Optional

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

from .database import SessionLocal
from .models import Account
from .token_service import decrypt, encrypt

SCOPES = [
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube",
]


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _load_credentials(account: Account) -> Optional[Credentials]:
    if not account.encrypted_tokens:
        return None
    try:
        raw = decrypt(account.encrypted_tokens)
        if not raw:
            return None
        data = json.loads(raw)
        return Credentials.from_authorized_user_info(data, SCOPES)
    except Exception:
        return None


def _persist_credentials(session, account: Account, creds: Credentials) -> None:
    account.encrypted_tokens = encrypt(creds.to_json())
    session.add(account)


def auth_service(account_id: int):
    with session_scope() as session:
        account = session.get(Account, account_id)
        if not account:
            raise ValueError(f"Account {account_id} not found")

        creds = _load_credentials(account)
        refreshed = False
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                refreshed = True
            except Exception:
                creds = None
        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file("client_secret.json", SCOPES)
            creds = flow.run_local_server(port=0)
            refreshed = True
        if refreshed:
            _persist_credentials(session, account, creds)
    return build("youtube", "v3", credentials=creds)


def rfc3339(dt):
    return dt.replace(microsecond=0).isoformat("T") + "Z"


def upload_one(
    yt,
    video_path,
    title,
    description,
    tags,
    category_id,
    publish_at_iso,
    thumb_path=None,
    playlist_id=None,
):
    body = {
        "snippet": {
            "title": title,
            "description": description,
            "tags": tags,
            "categoryId": str(category_id),
        },
        "status": {
            "privacyStatus": "scheduled" if publish_at_iso else "public",
            **({"publishAt": publish_at_iso} if publish_at_iso else {}),
        },
    }
    media = MediaFileUpload(
        video_path, chunksize=-1, resumable=True, mimetype="video/*"
    )
    req = yt.videos().insert(part="snippet,status", body=body, media_body=media)
    resp = None
    while resp is None:
        status, resp = req.next_chunk()
    vid = resp["id"]
    if thumb_path:
        yt.thumbnails().set(videoId=vid, media_body=thumb_path).execute()
    if playlist_id:
        yt.playlistItems().insert(
            part="snippet",
            body={
                "snippet": {
                    "playlistId": playlist_id,
                    "resourceId": {"kind": "youtube#video", "videoId": vid},
                }
            },
        ).execute()
    return vid
