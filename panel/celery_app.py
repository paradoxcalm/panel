"""Инициализация Celery."""
from __future__ import annotations

import os

from celery import Celery


def _create_celery() -> Celery:
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    result_backend = os.getenv("CELERY_RESULT_BACKEND", broker_url)
    app = Celery(
        "panel",
        broker=broker_url,
        backend=result_backend,
        include=["panel.tasks"],
    )
    app.conf.update(
        timezone=os.getenv("CELERY_TIMEZONE", "UTC"),
        enable_utc=True,
        task_track_started=True,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        beat_schedule={
            "schedule-pending-jobs": {
                "task": "panel.tasks.schedule_pending_jobs",
                "schedule": int(os.getenv("SCHEDULER_INTERVAL_SECONDS", "60")),
            },
            "trigger-ready-jobs": {
                "task": "panel.tasks.trigger_ready_jobs",
                "schedule": int(os.getenv("SCHEDULER_TRIGGER_SECONDS", "60")),
            },
        },
    )
    return app


celery_app = _create_celery()

__all__ = ["celery_app"]
