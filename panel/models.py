import datetime as dt
from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String, Text, Time, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from database import Base


JSONType = JSON().with_variant(JSONB(astext_type=Text()), "postgresql")


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    timezone = Column(String(64), nullable=False, default="UTC")
    daily_cap = Column(Integer, nullable=False, default=10)
    quiet_hours_start = Column(Time, nullable=True)
    quiet_hours_end = Column(Time, nullable=True)
    theme = Column(String(255), nullable=True)
    encrypted_tokens = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow, nullable=False)

    channels = relationship("Channel", back_populates="account", cascade="all, delete-orphan")


class Channel(Base):
    __tablename__ = "channels"

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    timezone = Column(String(64), nullable=False, default="UTC")
    daily_cap = Column(Integer, nullable=False, default=10)
    quiet_hours_start = Column(Time, nullable=True)
    quiet_hours_end = Column(Time, nullable=True)
    theme = Column(String(255), nullable=True)
    encrypted_tokens = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow, nullable=False)

    account = relationship("Account", back_populates="channels")
    jobs = relationship("Job", back_populates="channel", cascade="all, delete-orphan")
    schedule_slots = relationship("ScheduleSlot", back_populates="channel", cascade="all, delete-orphan")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True)
    channel_id = Column(Integer, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    video_path = Column(String(1024), nullable=False)
    thumb_path = Column(String(1024), nullable=True)
    tags = Column(JSONType, nullable=False, default=list)
    category_id = Column(String(32), nullable=False, default="22")
    publish_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    youtube_video_id = Column(String(128), nullable=True)

    channel = relationship("Channel", back_populates="jobs")
    schedule_slot = relationship("ScheduleSlot", back_populates="job", uselist=False)


class ScheduleSlot(Base):
    __tablename__ = "schedule_slots"

    id = Column(Integer, primary_key=True)
    channel_id = Column(Integer, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(Integer, ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True)
    scheduled_for = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(32), nullable=False, default="reserved")
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)

    channel = relationship("Channel", back_populates="schedule_slots")
    job = relationship("Job", back_populates="schedule_slot")
