"""Механизмы уведомлений о статусе заданий."""
from __future__ import annotations

import os
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Optional

from .models import Job


def send_telegram_message(text: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False


def send_email_notification(subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    to_email = os.getenv("NOTIFY_EMAIL_TO")
    if not host or not to_email:
        return False
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("NOTIFY_EMAIL_FROM", username or "no-reply@example.com")
    use_tls = os.getenv("SMTP_USE_TLS", "1") != "0"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email
    message.set_content(body)

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.starttls(context=context)
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
        return True
    except Exception:
        return False


def notify_job_status(job: Job, success: bool, *, error: Optional[str] = None) -> None:
    status = "успешно" if success else "с ошибкой"
    title = f"Задание #{job.id} {status}"
    body = [
        f"Видео: {job.title}",
        f"Канал: {job.channel.name if job.channel else job.channel_id}",
    ]
    if job.youtube_video_id:
        body.append(f"Video ID: {job.youtube_video_id}")
    if error:
        body.append(f"Ошибка: {error}")
    body_text = "\n".join(body)

    send_telegram_message(f"{title}\n{body_text}")
    send_email_notification(title, body_text)


__all__ = ["notify_job_status", "send_telegram_message", "send_email_notification"]
