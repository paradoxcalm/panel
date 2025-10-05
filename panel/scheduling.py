"""Утилиты планировщика публикаций."""
from __future__ import annotations

import datetime as dt
import os
import random
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from zoneinfo import ZoneInfo
from sqlalchemy.orm import Session

from . import models
from .constants import (
    ACTIVE_JOB_STATUSES,
    DEFAULT_LOOKAHEAD_DAYS,
    DEFAULT_MIN_GAP_MINUTES,
    DEFAULT_RANDOM_MAX_MINUTES,
    DEFAULT_RANDOM_MIN_MINUTES,
)


@dataclass
class SchedulerSettings:
    random_min_minutes: int = DEFAULT_RANDOM_MIN_MINUTES
    random_max_minutes: int = DEFAULT_RANDOM_MAX_MINUTES
    min_gap_minutes: int = DEFAULT_MIN_GAP_MINUTES
    lookahead_days: int = DEFAULT_LOOKAHEAD_DAYS

    @classmethod
    def from_env(cls) -> "SchedulerSettings":
        return cls(
            random_min_minutes=int(
                os.getenv("SCHEDULER_RANDOM_MIN_MINUTES", DEFAULT_RANDOM_MIN_MINUTES)
            ),
            random_max_minutes=int(
                os.getenv("SCHEDULER_RANDOM_MAX_MINUTES", DEFAULT_RANDOM_MAX_MINUTES)
            ),
            min_gap_minutes=int(os.getenv("SCHEDULER_MIN_GAP_MINUTES", DEFAULT_MIN_GAP_MINUTES)),
            lookahead_days=int(os.getenv("SCHEDULER_LOOKAHEAD_DAYS", DEFAULT_LOOKAHEAD_DAYS)),
        )


@dataclass
class ChannelScheduleState:
    occupied: List[dt.datetime] = field(default_factory=list)
    extra_counts: Dict[dt.date, int] = field(default_factory=dict)

    def register(self, channel: models.Channel, scheduled_for: dt.datetime) -> None:
        self.occupied.append(scheduled_for)
        self.occupied.sort()
        tz = ZoneInfo(get_effective_timezone(channel))
        local_date = scheduled_for.astimezone(tz).date()
        self.extra_counts[local_date] = self.extra_counts.get(local_date, 0) + 1


def get_effective_timezone(channel: models.Channel) -> str:
    if channel.timezone:
        return channel.timezone
    if channel.account and channel.account.timezone:
        return channel.account.timezone
    return "UTC"


def get_effective_daily_cap(channel: models.Channel) -> Optional[int]:
    if channel.daily_cap:
        return channel.daily_cap
    if channel.account and channel.account.daily_cap:
        return channel.account.daily_cap
    return None


def get_effective_quiet_hours(
    channel: models.Channel,
) -> tuple[Optional[dt.time], Optional[dt.time]]:
    start = channel.quiet_hours_start or (
        channel.account.quiet_hours_start if channel.account else None
    )
    end = channel.quiet_hours_end or (
        channel.account.quiet_hours_end if channel.account else None
    )
    return start, end


def move_out_of_quiet_hours(
    local_dt: dt.datetime, start: Optional[dt.time], end: Optional[dt.time]
) -> dt.datetime:
    if not start or not end or start == end:
        return local_dt
    while True:
        current_time = local_dt.time()
        if start < end:
            if start <= current_time < end:
                local_dt = local_dt.replace(
                    hour=end.hour,
                    minute=end.minute,
                    second=0,
                    microsecond=0,
                )
                continue
            break
        if current_time >= start:
            next_date = local_dt.date() + dt.timedelta(days=1)
            local_dt = dt.datetime.combine(next_date, end, tzinfo=local_dt.tzinfo)
            continue
        if current_time < end:
            local_dt = dt.datetime.combine(local_dt.date(), end, tzinfo=local_dt.tzinfo)
            continue
        break
    return local_dt


def count_jobs_for_day(
    session: Session,
    channel: models.Channel,
    local_date: dt.date,
    *,
    exclude_job_id: Optional[int] = None,
) -> int:
    tz = ZoneInfo(get_effective_timezone(channel))
    start_local = dt.datetime.combine(local_date, dt.time.min, tzinfo=tz)
    end_local = start_local + dt.timedelta(days=1)
    start_utc = start_local.astimezone(dt.timezone.utc)
    end_utc = end_local.astimezone(dt.timezone.utc)
    query = (
        session.query(models.Job)
        .filter(models.Job.channel_id == channel.id)
        .filter(models.Job.publish_at.isnot(None))
        .filter(models.Job.publish_at >= start_utc)
        .filter(models.Job.publish_at < end_utc)
        .filter(models.Job.status.in_(ACTIVE_JOB_STATUSES))
    )
    if exclude_job_id is not None:
        query = query.filter(models.Job.id != exclude_job_id)
    return query.count()


def apply_channel_limits(
    session: Session,
    channel: models.Channel,
    candidate_utc: dt.datetime,
    *,
    extra_counts: Optional[Dict[dt.date, int]] = None,
    exclude_job_id: Optional[int] = None,
) -> dt.datetime:
    tz = ZoneInfo(get_effective_timezone(channel))
    local_dt = candidate_utc.astimezone(tz)
    start, end = get_effective_quiet_hours(channel)
    local_dt = move_out_of_quiet_hours(local_dt, start, end)
    cap = get_effective_daily_cap(channel)
    if cap and cap > 0:
        extra_counts = extra_counts or {}
        while (
            count_jobs_for_day(
                session, channel, local_dt.date(), exclude_job_id=exclude_job_id
            )
            + extra_counts.get(local_dt.date(), 0)
            >= cap
        ):
            next_date = local_dt.date() + dt.timedelta(days=1)
            local_dt = dt.datetime.combine(next_date, local_dt.time(), tzinfo=tz)
            local_dt = move_out_of_quiet_hours(local_dt, start, end)
    return local_dt.astimezone(dt.timezone.utc)


def _nearest_conflict(
    candidate: dt.datetime, occupied: Iterable[dt.datetime], min_gap: dt.timedelta
) -> Optional[dt.datetime]:
    for existing in sorted(occupied):
        if abs(existing - candidate) < min_gap:
            return existing
    return None


def find_slot_for_job(
    session: Session,
    job: models.Job,
    *,
    desired_utc: Optional[dt.datetime] = None,
    occupied: Optional[Iterable[dt.datetime]] = None,
    extra_counts: Optional[Dict[dt.date, int]] = None,
    settings: Optional[SchedulerSettings] = None,
) -> Optional[dt.datetime]:
    settings = settings or SchedulerSettings.from_env()
    occupied_list = list(occupied or [])
    extra_counts = extra_counts or {}
    now = dt.datetime.now(dt.timezone.utc)
    min_gap = dt.timedelta(minutes=max(settings.min_gap_minutes, 0))
    if desired_utc is not None:
        candidate = desired_utc
    else:
        base = now + dt.timedelta(
            minutes=random.randint(
                min(settings.random_min_minutes, settings.random_max_minutes),
                max(settings.random_min_minutes, settings.random_max_minutes),
            )
        )
        candidate = base
    if candidate < now:
        candidate = now
    attempts = max(settings.lookahead_days * 48, 1)
    for _ in range(attempts):
        candidate = apply_channel_limits(
            session,
            job.channel,
            candidate,
            extra_counts=extra_counts,
            exclude_job_id=job.id,
        )
        conflict = _nearest_conflict(candidate, occupied_list, min_gap)
        if not conflict:
            return candidate
        candidate = max(candidate, conflict + min_gap)
    return None


def load_channel_state(
    session: Session, channel: models.Channel, *, exclude_job_id: Optional[int] = None
) -> ChannelScheduleState:
    query = (
        session.query(models.Job.publish_at)
        .filter(models.Job.channel_id == channel.id)
        .filter(models.Job.publish_at.isnot(None))
        .filter(models.Job.status.in_(ACTIVE_JOB_STATUSES))
        .order_by(models.Job.publish_at)
    )
    if exclude_job_id is not None:
        query = query.filter(models.Job.id != exclude_job_id)
    state = ChannelScheduleState()
    for (value,) in query.all():
        if value is None:
            continue
        state.register(channel, value)
    return state


__all__ = [
    "SchedulerSettings",
    "ChannelScheduleState",
    "get_effective_timezone",
    "get_effective_daily_cap",
    "get_effective_quiet_hours",
    "move_out_of_quiet_hours",
    "count_jobs_for_day",
    "apply_channel_limits",
    "find_slot_for_job",
    "load_channel_state",
]
