# uploader.py
import os, datetime, pickle
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

SCOPES = ["https://www.googleapis.com/auth/youtube.upload","https://www.googleapis.com/auth/youtube"]

def auth_service():
    creds=None
    if os.path.exists("token.pickle"):
        with open("token.pickle","rb") as f: creds=pickle.load(f)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token: creds.refresh(Request())
        else:
            flow=InstalledAppFlow.from_client_secrets_file("client_secret.json", SCOPES)
            creds=flow.run_local_server(port=0)
        with open("token.pickle","wb") as f: pickle.dump(creds,f)
    return build("youtube","v3",credentials=creds)

def rfc3339(dt): return dt.replace(microsecond=0).isoformat("T")+"Z"

def upload_one(yt, video_path, title, description, tags, category_id, publish_at_iso, thumb_path=None, playlist_id=None):
    body={
      "snippet":{"title":title,"description":description,"tags":tags,"categoryId":str(category_id)},
      "status":{"privacyStatus":"scheduled" if publish_at_iso else "public", **({"publishAt":publish_at_iso} if publish_at_iso else {})}
    }
    media=MediaFileUpload(video_path,chunksize=-1,resumable=True,mimetype="video/*")
    req=yt.videos().insert(part="snippet,status",body=body,media_body=media)
    resp=None
    while resp is None:
        status, resp = req.next_chunk()
    vid=resp["id"]
    if thumb_path and os.path.exists(thumb_path):
        yt.thumbnails().set(videoId=vid, media_body=thumb_path).execute()
    if playlist_id:
        yt.playlistItems().insert(part="snippet", body={"snippet":{"playlistId":playlist_id,"resourceId":{"kind":"youtube#video","videoId":vid}}}).execute()
    return vid
