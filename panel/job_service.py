"""Служебные функции для работы с заданиями."""
from __future__ import annotations

import datetime as dt
from typing import Any, Dict, Optional

from zoneinfo import ZoneInfo
from sqlalchemy.orm import Session

from .models import Job, JobLog
from .scheduling import get_effective_timezone


def add_job_log(
    session: Session,
    job: Job,
    event: str,
    *,
    level: str = "info",
    message: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> JobLog:
    entry = JobLog(
        job_id=job.id,
        event=event,
        level=level,
        message=message,
        payload=payload or {},
        created_at=dt.datetime.now(dt.timezone.utc),
    )
    session.add(entry)
    return entry


def job_to_dict(job: Job) -> Dict[str, Any]:
    tz_name = get_effective_timezone(job.channel) if job.channel else None
    publish_utc = job.publish_at
    if publish_utc and publish_utc.tzinfo is None:
        publish_utc = publish_utc.replace(tzinfo=dt.timezone.utc)
    local_iso: Optional[str] = None
    if publish_utc and tz_name:
        local_iso = publish_utc.astimezone(ZoneInfo(tz_name)).isoformat()
    elif publish_utc:
        local_iso = publish_utc.isoformat()

    return {
        "id": job.id,
        "title": job.title,
        "status": job.status,
        "channel": job.channel.name if job.channel else None,
        "channel_id": job.channel_id,
        "publish_at": publish_utc.isoformat() if publish_utc else None,
        "publish_at_local": local_iso,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "error_message": job.error_message,
        "video_path": job.video_path,
        "thumb_path": job.thumb_path,
        "tags": job.tags,
        "category_id": job.category_id,
        "template_id": job.template_id,
        "template_context": job.template_context,
        "youtube_video_id": job.youtube_video_id,
        "schedule_slot": job.schedule_slot.scheduled_for.isoformat()
        if job.schedule_slot and job.schedule_slot.scheduled_for
        else None,
        "schedule_slot_status": job.schedule_slot.status if job.schedule_slot else None,
        "timezone": tz_name,
        "celery_task_id": job.celery_task_id,
    }


def job_log_to_dict(entry: JobLog) -> Dict[str, Any]:
    return {
        "id": entry.id,
        "job_id": entry.job_id,
        "event": entry.event,
        "level": entry.level,
        "message": entry.message,
        "payload": entry.payload,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


__all__ = ["add_job_log", "job_to_dict", "job_log_to_dict"]
