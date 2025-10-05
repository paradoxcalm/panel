import datetime as dt
from typing import Optional

from flask_login import UserMixin
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    Time,
    JSON,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

from .database import Base


JSONType = JSON().with_variant(JSONB(astext_type=Text()), "postgresql")


user_roles_table = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False, unique=True)
    description = Column(Text, nullable=True)

    users = relationship("User", secondary=user_roles_table, back_populates="roles")


class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=False, unique=True)
    display_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    sso_token_hash = Column(String(255), nullable=True)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=dt.datetime.utcnow,
        onupdate=dt.datetime.utcnow,
        nullable=False,
    )

    roles = relationship(
        "Role",
        secondary=user_roles_table,
        back_populates="users",
        lazy="joined",
    )

    @property  # type: ignore[override]
    def is_active(self) -> bool:
        return bool(self.is_enabled)

    def set_password(self, password: Optional[str]) -> None:
        """Установить хэш пароля для пользователя."""
        if password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None

    def check_password(self, password: Optional[str]) -> bool:
        if not password or not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def set_sso_token(self, token: Optional[str]) -> None:
        """Сохранить хэш SSO-токена."""
        if token:
            self.sso_token_hash = generate_password_hash(token)
        else:
            self.sso_token_hash = None

    def check_sso_token(self, token: Optional[str]) -> bool:
        if not token or not self.sso_token_hash:
            return False
        return check_password_hash(self.sso_token_hash, token)

    def has_role(self, role_name: str) -> bool:
        return any(role.name == role_name for role in self.roles)

    def has_any_role(self, *role_names: str) -> bool:
        if not role_names:
            return True
        target = set(role_names)
        return any(role.name in target for role in self.roles)


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
    status = Column(String(32), nullable=False, default="queued")
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    youtube_video_id = Column(String(128), nullable=True)
    template_id = Column(Integer, ForeignKey("templates.id", ondelete="SET NULL"), nullable=True)
    template_context = Column(JSONType, nullable=False, default=dict)
    celery_task_id = Column(String(255), nullable=True)

    channel = relationship("Channel", back_populates="jobs")
    schedule_slot = relationship("ScheduleSlot", back_populates="job", uselist=False)
    template = relationship("Template")
    logs = relationship(
        "JobLog",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobLog.created_at",
    )


class Template(Base):
    __tablename__ = "templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(255), nullable=True, unique=True)
    type = Column(String(64), nullable=False, default="description")
    body = Column(Text, nullable=False)
    platform = Column(String(64), nullable=True)
    utm_sets = Column(JSONType, nullable=False, default=dict)
    default_context = Column(JSONType, nullable=False, default=dict)
    default_tags = Column(JSONType, nullable=False, default=list)
    topics = Column(JSONType, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=dt.datetime.utcnow,
        onupdate=dt.datetime.utcnow,
        nullable=False,
    )


class Link(Base):
    __tablename__ = "links"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), nullable=False, unique=True)
    url = Column(String(1024), nullable=False)
    description = Column(Text, nullable=True)
    platform = Column(String(64), nullable=True)
    utm_params = Column(JSONType, nullable=False, default=dict)
    metadata = Column(JSONType, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=dt.datetime.utcnow,
        onupdate=dt.datetime.utcnow,
        nullable=False,
    )


class TagLibrary(Base):
    __tablename__ = "tag_library"

    id = Column(Integer, primary_key=True)
    tag = Column(String(255), nullable=False, unique=True)
    category = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=dt.datetime.utcnow,
        onupdate=dt.datetime.utcnow,
        nullable=False,
    )


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


class JobLog(Base):
    __tablename__ = "job_logs"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    event = Column(String(255), nullable=False)
    level = Column(String(32), nullable=False, default="info")
    message = Column(Text, nullable=True)
    payload = Column(JSONType, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=dt.datetime.utcnow, nullable=False)

    job = relationship("Job", back_populates="logs")
