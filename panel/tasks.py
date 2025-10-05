"""Фоновые задачи Celery."""
from __future__ import annotations

import datetime as dt
from typing import Dict

from celery.utils.log import get_task_logger
from sqlalchemy.orm import joinedload

from .celery_app import celery_app
from .database import SessionLocal
from .job_service import add_job_log
from .models import Job, ScheduleSlot
from .notifications import notify_job_status
from .scheduling import (
    ChannelScheduleState,
    SchedulerSettings,
    find_slot_for_job,
    load_channel_state,
)
from .uploader import auth_service, rfc3339, upload_one

logger = get_task_logger(__name__)


@celery_app.task(name="panel.tasks.schedule_pending_jobs")
def schedule_pending_jobs() -> int:
    """Подобрать слоты для заданий в статусе queued."""
    settings = SchedulerSettings.from_env()
    assigned = 0
    with SessionLocal() as session:
        jobs = (
            session.query(Job)
            .options(joinedload(Job.channel).joinedload("account"), joinedload(Job.schedule_slot))
            .filter(Job.status == "queued")
            .order_by(Job.created_at)
            .all()
        )
        channel_states: Dict[int, ChannelScheduleState] = {}
        for job in jobs:
            channel = job.channel
            if not channel:
                add_job_log(
                    session,
                    job,
                    "scheduler.error",
                    level="error",
                    message="Канал недоступен, задание помечено как failed",
                )
                job.status = "failed"
                job.error_message = "Канал недоступен"
                session.flush()
                continue
            state = channel_states.get(channel.id)
            if state is None:
                state = load_channel_state(session, channel, exclude_job_id=job.id)
                channel_states[channel.id] = state
            scheduled_for = find_slot_for_job(
                session,
                job,
                occupied=state.occupied,
                extra_counts=state.extra_counts,
                settings=settings,
            )
            if not scheduled_for:
                add_job_log(
                    session,
                    job,
                    "scheduler.no-slot",
                    level="warning",
                    message="Не удалось подобрать слот в пределах горизонта",
                )
                continue
            job.publish_at = scheduled_for
            job.status = "scheduled"
            job.started_at = None
            job.completed_at = None
            job.error_message = None
            if job.schedule_slot:
                job.schedule_slot.scheduled_for = scheduled_for
                job.schedule_slot.status = "reserved"
            else:
                slot = ScheduleSlot(
                    channel_id=channel.id,
                    job_id=job.id,
                    scheduled_for=scheduled_for,
                    status="reserved",
                )
                session.add(slot)
            add_job_log(
                session,
                job,
                "scheduler.assigned",
                payload={"scheduled_for": scheduled_for.isoformat()},
            )
            state.register(channel, scheduled_for)
            session.flush()
            assigned += 1
        session.commit()
    logger.info("Scheduled %s jobs", assigned)
    return assigned


@celery_app.task(name="panel.tasks.trigger_ready_jobs")
def trigger_ready_jobs() -> int:
    now = dt.datetime.now(dt.timezone.utc)
    dispatched = 0
    with SessionLocal() as session:
        jobs = (
            session.query(Job)
            .options(joinedload(Job.channel).joinedload("account"), joinedload(Job.schedule_slot))
            .filter(Job.status == "scheduled")
            .filter(Job.publish_at.isnot(None))
            .filter(Job.publish_at <= now)
            .all()
        )
        for job in jobs:
            job.status = "processing"
            job.started_at = now
            job.error_message = None
            if job.schedule_slot:
                job.schedule_slot.status = "processing"
            async_result = process_job_upload.delay(job.id)
            job.celery_task_id = async_result.id
            add_job_log(
                session,
                job,
                "upload.enqueued",
                payload={"task_id": async_result.id},
            )
            session.flush()
            dispatched += 1
        session.commit()
    if dispatched:
        logger.info("Dispatched %s jobs for upload", dispatched)
    return dispatched


@celery_app.task(name="panel.tasks.process_job_upload", bind=True)
def process_job_upload(self, job_id: int) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    success = False
    error_message = None
    with SessionLocal() as session:
        job = session.get(
            Job,
            job_id,
            options=(
                joinedload(Job.channel).joinedload("account"),
                joinedload(Job.schedule_slot),
            ),
        )
        if not job:
            logger.warning("Job %s not found", job_id)
            return
        job.celery_task_id = self.request.id
        if job.started_at is None:
            job.started_at = now
        add_job_log(session, job, "upload.started")
        session.flush()
        try:
            channel = job.channel
            if not channel or not channel.account:
                raise RuntimeError("У задания отсутствует канал или аккаунт")
            yt = auth_service(channel.account.id)
            publish_at_iso = rfc3339(job.publish_at) if job.publish_at else None
            video_id = upload_one(
                yt,
                video_path=job.video_path,
                title=job.title,
                description=job.description,
                tags=job.tags,
                category_id=job.category_id,
                publish_at_iso=publish_at_iso,
                thumb_path=job.thumb_path,
            )
            job.youtube_video_id = video_id
            job.status = "completed"
            job.completed_at = dt.datetime.now(dt.timezone.utc)
            job.error_message = None
            if job.schedule_slot:
                job.schedule_slot.status = "completed"
            add_job_log(
                session,
                job,
                "upload.completed",
                payload={"video_id": video_id},
            )
            success = True
        except Exception as exc:  # pragma: no cover - защитный код
            error_message = str(exc)
            job.status = "failed"
            job.error_message = error_message
            if job.schedule_slot:
                job.schedule_slot.status = "failed"
            add_job_log(
                session,
                job,
                "upload.failed",
                level="error",
                message=error_message,
            )
            logger.exception("Не удалось выполнить загрузку задания %s", job_id)
        finally:
            session.flush()
            session.commit()
            notify_job_status(job, success, error=error_message)
    return None
