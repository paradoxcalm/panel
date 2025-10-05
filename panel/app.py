import datetime as dt
import os
import random
from contextlib import contextmanager
from functools import wraps
from typing import Dict, Iterable, List, Optional
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session as flask_session,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy import case
from sqlalchemy.orm import joinedload
from waitress import serve

from database import DATA_DIR, SessionLocal, init_db
from models import Account, Channel, Job, Role, ScheduleSlot, User
from uploader import auth_service, rfc3339, upload_one

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Авторизуйтесь для доступа."

ROLE_OWNER = "owner"
ROLE_EDITOR = "editor"
ROLE_VIEWER = "viewer"
ALL_ROLES = (ROLE_OWNER, ROLE_EDITOR, ROLE_VIEWER)

UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

init_db()


def bootstrap_auth() -> None:
    """Создать роли и базового пользователя при первом запуске."""
    session = SessionLocal()
    try:
        roles = {
            role.name: role
            for role in session.query(Role).filter(Role.name.in_(ALL_ROLES))
        }
        changed = False
        for role_name in ALL_ROLES:
            if role_name not in roles:
                role = Role(name=role_name)
                session.add(role)
                roles[role_name] = role
                changed = True
        if changed:
            session.flush()

        owner_exists = (
            session.query(User)
            .join(User.roles)
            .filter(Role.name == ROLE_OWNER)
            .count()
            > 0
        )
        if not owner_exists and session.query(User).count() == 0:
            default_owner = User(username="admin", display_name="Administrator")
            default_owner.set_password("admin")
            default_owner.roles.append(roles[ROLE_OWNER])
            session.add(default_owner)
            session.flush()
            app.logger.warning(
                "Создан пользователь admin с ролью owner. Измените пароль после входа."
            )
        session.commit()
    finally:
        session.close()


bootstrap_auth()

ACTIVE_JOB_STATUSES = ("pending", "processing")


@contextmanager
def db_session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    if not user_id:
        return None
    session = SessionLocal()
    try:
        user = session.get(User, int(user_id), options=(joinedload(User.roles),))
        if user is not None:
            session.expunge(user)
        return user
    finally:
        session.close()


@login_manager.unauthorized_handler
def on_unauthorized():
    flash("Авторизуйтесь для доступа.")
    return redirect(url_for("login"))


def roles_required(*role_names: str):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not current_user.has_any_role(*role_names):
                abort(403)
            return func(*args, **kwargs)

        return wrapper

    return decorator


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password")
        session = SessionLocal()
        try:
            user = (
                session.query(User)
                .options(joinedload(User.roles))
                .filter(User.username == username)
                .first()
            )
            if not user or not user.check_password(password):
                error = "Неверное имя пользователя или пароль"
            elif not user.is_active:
                error = "Пользователь деактивирован"
            else:
                default_url = url_for("index") if user.has_any_role(ROLE_EDITOR, ROLE_OWNER) else url_for("queue_view")
                session.expunge(user)
                login_user(user)
                flash("Добро пожаловать!")
                next_url = request.args.get("next") or default_url
                return redirect(next_url)
        finally:
            session.close()
        if error:
            flash(error)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы")
    return redirect(url_for("login"))


def _load_roles(session) -> Dict[str, Role]:
    roles = session.query(Role).filter(Role.name.in_(ALL_ROLES)).all()
    return {role.name: role for role in roles}


def _ensure_not_last_owner(session, *, exclude_user_id: Optional[int] = None) -> bool:
    owners_query = session.query(User).join(User.roles).filter(Role.name == ROLE_OWNER)
    if exclude_user_id is not None:
        owners_query = owners_query.filter(User.id != exclude_user_id)
    return owners_query.count() > 0


@app.route("/users")
@roles_required(ROLE_OWNER)
def users_list():
    session = SessionLocal()
    try:
        users = (
            session.query(User)
            .options(joinedload(User.roles))
            .order_by(User.username)
            .all()
        )
        roles = session.query(Role).order_by(Role.name).all()
    finally:
        session.close()
    return render_template("users.html", users=users, roles=roles)


@app.route("/users/create", methods=["POST"])
@roles_required(ROLE_OWNER)
def users_create():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password")
    display_name = (request.form.get("display_name") or "").strip() or None
    sso_token = request.form.get("sso_token")
    selected_roles = set(request.form.getlist("roles"))

    if not username:
        flash("Имя пользователя обязательно")
        return redirect(url_for("users_list"))

    session = SessionLocal()
    try:
        if session.query(User).filter(User.username == username).first():
            flash("Пользователь с таким именем уже существует")
            return redirect(url_for("users_list"))

        role_map = _load_roles(session)
        user = User(username=username, display_name=display_name)
        user.set_password(password)
        user.set_sso_token(sso_token)

        if not selected_roles:
            selected_roles = {ROLE_VIEWER}
        for role_name in selected_roles:
            role = role_map.get(role_name)
            if role:
                user.roles.append(role)

        session.add(user)
        session.commit()
    finally:
        session.close()

    flash("Пользователь создан")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/update", methods=["POST"])
@roles_required(ROLE_OWNER)
def users_update(user_id: int):
    password = request.form.get("password")
    display_name = (request.form.get("display_name") or "").strip() or None
    sso_token = request.form.get("sso_token")
    clear_sso = request.form.get("clear_sso") == "1"
    is_enabled = request.form.get("is_enabled") == "on"
    selected_roles = set(request.form.getlist("roles"))

    session = SessionLocal()
    try:
        user = session.get(User, user_id, options=(joinedload(User.roles),))
        if not user:
            flash("Пользователь не найден")
            return redirect(url_for("users_list"))

        if current_user.id == user.id and ROLE_OWNER not in selected_roles:
            selected_roles.add(ROLE_OWNER)

        if ROLE_OWNER not in selected_roles and user.has_role(ROLE_OWNER):
            if not _ensure_not_last_owner(session, exclude_user_id=user.id):
                flash("Нельзя лишить последнего владельца роли Owner")
                return redirect(url_for("users_list"))

        if not is_enabled and user.has_role(ROLE_OWNER):
            if not _ensure_not_last_owner(session, exclude_user_id=user.id):
                flash("Нельзя деактивировать последнего владельца")
                return redirect(url_for("users_list"))

        user.display_name = display_name
        user.is_enabled = is_enabled
        if password:
            user.set_password(password)
        if clear_sso:
            user.set_sso_token(None)
        elif sso_token:
            user.set_sso_token(sso_token)

        role_map = _load_roles(session)
        if not selected_roles:
            selected_roles = {ROLE_VIEWER}

        current_roles = {role.name for role in user.roles}
        for role in list(user.roles):
            if role.name not in selected_roles:
                user.roles.remove(role)
        for role_name in selected_roles:
            if role_name not in current_roles and role_name in role_map:
                user.roles.append(role_map[role_name])

        session.add(user)
        session.commit()
    finally:
        session.close()

    flash("Данные пользователя обновлены")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@roles_required(ROLE_OWNER)
def users_delete(user_id: int):
    if current_user.id == user_id:
        flash("Нельзя удалить собственный профиль")
        return redirect(url_for("users_list"))

    session = SessionLocal()
    try:
        user = session.get(User, user_id, options=(joinedload(User.roles),))
        if not user:
            flash("Пользователь не найден")
            return redirect(url_for("users_list"))

        if user.has_role(ROLE_OWNER) and not _ensure_not_last_owner(session, exclude_user_id=user.id):
            flash("Нельзя удалить последнего владельца")
            return redirect(url_for("users_list"))

        session.delete(user)
        session.commit()
    finally:
        session.close()

    flash("Пользователь удалён")
    return redirect(url_for("users_list"))


def ensure_active_account(session) -> Optional[Account]:
    account_id = flask_session.get("active_account_id")
    account = None
    if account_id:
        account = session.get(Account, account_id)
    if not account:
        account = session.query(Account).order_by(Account.id).first()
        if account:
            flask_session["active_account_id"] = account.id
    return account


def get_effective_timezone(channel: Channel) -> str:
    if channel.timezone:
        return channel.timezone
    if channel.account and channel.account.timezone:
        return channel.account.timezone
    return "UTC"


def get_effective_daily_cap(channel: Channel) -> Optional[int]:
    if channel.daily_cap:
        return channel.daily_cap
    if channel.account and channel.account.daily_cap:
        return channel.account.daily_cap
    return None


def get_effective_quiet_hours(channel: Channel) -> tuple[Optional[dt.time], Optional[dt.time]]:
    start = channel.quiet_hours_start or (channel.account.quiet_hours_start if channel.account else None)
    end = channel.quiet_hours_end or (channel.account.quiet_hours_end if channel.account else None)
    return start, end


def move_out_of_quiet_hours(local_dt: dt.datetime, start: Optional[dt.time], end: Optional[dt.time]) -> dt.datetime:
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
        else:
            if current_time >= start:
                next_date = local_dt.date() + dt.timedelta(days=1)
                local_dt = dt.datetime.combine(
                    next_date,
                    end,
                    tzinfo=local_dt.tzinfo,
                )
                continue
            if current_time < end:
                local_dt = dt.datetime.combine(
                    local_dt.date(),
                    end,
                    tzinfo=local_dt.tzinfo,
                )
                continue
            break
    return local_dt


def count_jobs_for_day(session, channel: Channel, local_date: dt.date) -> int:
    tz = ZoneInfo(get_effective_timezone(channel))
    start_local = dt.datetime.combine(local_date, dt.time.min, tzinfo=tz)
    end_local = start_local + dt.timedelta(days=1)
    start_utc = start_local.astimezone(dt.timezone.utc)
    end_utc = end_local.astimezone(dt.timezone.utc)
    return (
        session.query(Job)
        .filter(
            Job.channel_id == channel.id,
            Job.publish_at.isnot(None),
            Job.publish_at >= start_utc,
            Job.publish_at < end_utc,
            Job.status.in_(ACTIVE_JOB_STATUSES),
        )
        .count()
    )


def apply_channel_limits(session, channel: Channel, candidate_utc: dt.datetime) -> dt.datetime:
    tz_name = get_effective_timezone(channel)
    tz = ZoneInfo(tz_name)
    local_dt = candidate_utc.astimezone(tz)
    start, end = get_effective_quiet_hours(channel)
    local_dt = move_out_of_quiet_hours(local_dt, start, end)
    cap = get_effective_daily_cap(channel)
    if cap and cap > 0:
        while count_jobs_for_day(session, channel, local_dt.date()) >= cap:
            next_date = local_dt.date() + dt.timedelta(days=1)
            local_dt = dt.datetime.combine(next_date, local_dt.time(), tzinfo=tz)
            local_dt = move_out_of_quiet_hours(local_dt, start, end)
    return local_dt.astimezone(dt.timezone.utc)


def parse_time(value: str) -> Optional[dt.time]:
    if not value:
        return None
    try:
        return dt.time.fromisoformat(value)
    except ValueError:
        return None


@app.template_filter("in_tz")
def localize(value: Optional[dt.datetime], tz_name: Optional[str]):
    if value is None or not tz_name:
        return value
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        return value
    return value.astimezone(tz)


@app.context_processor
def inject_navigation():
    accounts: List[Account] = []
    if current_user.is_authenticated:
        session = SessionLocal()
        try:
            accounts = (
                session.query(Account)
                .options(joinedload(Account.channels))
                .order_by(Account.name)
                .all()
            )
        finally:
            session.close()

    def has_role(role_name: str) -> bool:
        return current_user.is_authenticated and current_user.has_role(role_name)

    return {
        "nav_accounts": accounts,
        "active_account_id": flask_session.get("active_account_id"),
        "ROLE_OWNER": ROLE_OWNER,
        "ROLE_EDITOR": ROLE_EDITOR,
        "ROLE_VIEWER": ROLE_VIEWER,
        "has_role": has_role,
    }


@app.route("/")
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def index():
    session = SessionLocal()
    try:
        account = ensure_active_account(session)
        channels: Iterable[Channel] = []
        queue: Iterable[Job] = []
        if account:
            channels = (
                session.query(Channel)
                .filter(Channel.account_id == account.id)
                .order_by(Channel.name)
                .all()
            )
            queue = (
                session.query(Job)
                .options(joinedload(Job.channel))
                .join(Channel)
                .filter(Channel.account_id == account.id)
                .order_by(Job.created_at)
                .all()
            )
        return render_template("index.html", account=account, channels=channels, queue=queue)
    finally:
        session.close()


@app.route("/upload", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def upload():
    channel_id = request.form.get("channel_id", type=int)
    session = SessionLocal()
    try:
        channel = session.get(Channel, channel_id, options=(joinedload(Channel.account),)) if channel_id else None
        if not channel:
            flash("Выберите канал для загрузки")
            return redirect(url_for("index"))

        video_file = request.files.get("video")
        if not video_file or not video_file.filename:
            flash("Не выбрано видео")
            return redirect(url_for("index"))
        thumb_file = request.files.get("thumb")
        title = request.form.get("title") or os.path.splitext(video_file.filename)[0]
        desc = request.form.get("description") or ""
        tg = request.form.get("tg") or ""
        tags = [t.strip() for t in (request.form.get("tags") or "").split(",") if t.strip()]
        category_id = request.form.get("categoryId") or "22"
        mode = request.form.get("mode")

        video_path = os.path.join(UPLOAD_DIR, video_file.filename)
        video_file.save(video_path)
        thumb_path = None
        if thumb_file and thumb_file.filename:
            thumb_path = os.path.join(UPLOAD_DIR, thumb_file.filename)
            thumb_file.save(thumb_path)

        publish_at_utc = None
        if mode == "schedule":
            date_str = request.form.get("date")
            time_str = request.form.get("time")
            if date_str and time_str:
                tz = ZoneInfo(get_effective_timezone(channel))
                local_dt = dt.datetime.fromisoformat(f"{date_str}T{time_str}")
                local_dt = local_dt.replace(tzinfo=tz)
                publish_at_utc = local_dt.astimezone(dt.timezone.utc)
        elif mode == "random":
            min_h = float(request.form.get("min_h", 1))
            max_h = float(request.form.get("max_h", 3))
            start_dt = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
            delta = random.uniform(min_h, max_h)
            publish_at_utc = start_dt + dt.timedelta(hours=delta)

        if publish_at_utc:
            publish_at_utc = apply_channel_limits(session, channel, publish_at_utc)

        description = (desc + (f"\nПодпишись на Telegram: {tg}" if tg else "")).strip()
        job = Job(
            channel_id=channel.id,
            title=title,
            description=description,
            tags=tags or ["youtube", "shorts"],
            category_id=category_id,
            publish_at=publish_at_utc,
            video_path=video_path,
            thumb_path=thumb_path,
            status="pending",
        )
        session.add(job)
        session.flush()
        slot_time = publish_at_utc or dt.datetime.now(dt.timezone.utc)
        slot = ScheduleSlot(
            channel_id=channel.id,
            job_id=job.id,
            scheduled_for=slot_time,
            status="reserved",
        )
        session.add(slot)
        session.commit()
        flash("Добавлено в очередь")
    finally:
        session.close()
    return redirect(url_for("index"))


@app.route("/queue")
@roles_required(ROLE_VIEWER, ROLE_EDITOR, ROLE_OWNER)
def queue_view():
    session = SessionLocal()
    try:
        account = ensure_active_account(session)
        items: Iterable[Job] = []
        if account:
            items = (
                session.query(Job)
                .options(joinedload(Job.channel))
                .join(Channel)
                .filter(Channel.account_id == account.id)
                .order_by(Job.created_at)
                .all()
            )
        return render_template("queue.html", queue=items, account=account)
    finally:
        session.close()


@app.route("/start", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def start():
    session = SessionLocal()
    try:
        account = ensure_active_account(session)
        if not account:
            flash("Создайте аккаунт и канал перед загрузкой")
            return redirect(url_for("index"))
        order_expression = case((Job.publish_at.is_(None), 0), else_=1)
        job_ids = [
            job.id
            for job in (
                session.query(Job)
                .join(Channel)
                .filter(Channel.account_id == account.id, Job.status == "pending")
                .order_by(order_expression, Job.publish_at, Job.created_at)
                .all()
            )
        ]
    finally:
        session.close()

    if not job_ids:
        flash("Очередь пуста")
        return redirect(url_for("index"))

    yt = auth_service(account.id)

    errors = 0
    session = SessionLocal()
    try:
        for job_id in job_ids:
            job = session.get(Job, job_id, options=(joinedload(Job.schedule_slot), joinedload(Job.channel)))
            if not job:
                continue
            job.status = "processing"
            job.started_at = dt.datetime.now(dt.timezone.utc)
            session.flush()
            try:
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
                job.status = "completed"
                job.youtube_video_id = video_id
                job.completed_at = dt.datetime.now(dt.timezone.utc)
                if job.schedule_slot:
                    job.schedule_slot.status = "completed"
            except Exception as exc:  # pragma: no cover - runtime safety
                job.status = "failed"
                job.error_message = str(exc)
                if job.schedule_slot:
                    job.schedule_slot.status = "failed"
                errors += 1
            session.flush()
        session.commit()
    finally:
        session.close()

    flash(f"Готово. Ошибок: {errors}")
    return redirect(url_for("index"))


@app.route("/switch-account/<int:account_id>", methods=["POST"])
@roles_required(ROLE_VIEWER, ROLE_EDITOR, ROLE_OWNER)
def switch_account(account_id: int):
    session = SessionLocal()
    try:
        account = session.get(Account, account_id)
        if not account:
            flash("Аккаунт не найден")
        else:
            flask_session["active_account_id"] = account.id
    finally:
        session.close()
    return redirect(request.referrer or url_for("index"))


@app.route("/accounts")
@roles_required(ROLE_OWNER)
def accounts_view():
    session = SessionLocal()
    try:
        accounts = (
            session.query(Account)
            .options(joinedload(Account.channels))
            .order_by(Account.name)
            .all()
        )
        return render_template("accounts.html", accounts=accounts)
    finally:
        session.close()


@app.route("/accounts/create", methods=["POST"])
@roles_required(ROLE_OWNER)
def create_account():
    name = request.form.get("name")
    timezone = request.form.get("timezone") or "UTC"
    daily_cap = request.form.get("daily_cap", type=int)
    quiet_start = parse_time(request.form.get("quiet_start"))
    quiet_end = parse_time(request.form.get("quiet_end"))
    theme = request.form.get("theme")

    if not name:
        flash("Укажите название аккаунта")
        return redirect(url_for("accounts_view"))

    with db_session_scope() as session:
        account = Account(
            name=name,
            timezone=timezone,
            daily_cap=daily_cap if daily_cap is not None else 0,
            quiet_hours_start=quiet_start,
            quiet_hours_end=quiet_end,
            theme=theme,
        )
        session.add(account)
        session.flush()
        flask_session["active_account_id"] = account.id
    flash("Аккаунт создан")
    return redirect(url_for("accounts_view"))


@app.route("/accounts/<int:account_id>/update", methods=["POST"])
@roles_required(ROLE_OWNER)
def update_account(account_id: int):
    daily_cap = request.form.get("daily_cap", type=int)
    quiet_start = parse_time(request.form.get("quiet_start"))
    quiet_end = parse_time(request.form.get("quiet_end"))
    timezone = request.form.get("timezone") or "UTC"
    theme = request.form.get("theme")

    with db_session_scope() as session:
        account = session.get(Account, account_id)
        if not account:
            flash("Аккаунт не найден")
            return redirect(url_for("accounts_view"))
        if daily_cap is not None:
            account.daily_cap = daily_cap
        account.quiet_hours_start = quiet_start
        account.quiet_hours_end = quiet_end
        account.timezone = timezone
        account.theme = theme
        session.add(account)
    flash("Настройки аккаунта обновлены")
    return redirect(url_for("accounts_view"))


@app.route("/accounts/<int:account_id>/channels", methods=["POST"])
@roles_required(ROLE_OWNER)
def create_channel(account_id: int):
    name = request.form.get("name")
    timezone = request.form.get("timezone") or "UTC"
    daily_cap = request.form.get("daily_cap", type=int)
    quiet_start = parse_time(request.form.get("quiet_start"))
    quiet_end = parse_time(request.form.get("quiet_end"))
    theme = request.form.get("theme")

    if not name:
        flash("Укажите название канала")
        return redirect(url_for("accounts_view"))

    with db_session_scope() as session:
        account = session.get(Account, account_id)
        if not account:
            flash("Аккаунт не найден")
            return redirect(url_for("accounts_view"))
        channel = Channel(
            account_id=account.id,
            name=name,
            timezone=timezone,
            daily_cap=daily_cap if daily_cap is not None else account.daily_cap,
            quiet_hours_start=quiet_start,
            quiet_hours_end=quiet_end,
            theme=theme,
        )
        session.add(channel)
    flash("Канал добавлен")
    return redirect(url_for("accounts_view"))


@app.route("/channels/<int:channel_id>/update", methods=["POST"])
@roles_required(ROLE_OWNER)
def update_channel(channel_id: int):
    daily_cap = request.form.get("daily_cap", type=int)
    quiet_start = parse_time(request.form.get("quiet_start"))
    quiet_end = parse_time(request.form.get("quiet_end"))
    timezone = request.form.get("timezone") or "UTC"
    theme = request.form.get("theme")

    with db_session_scope() as session:
        channel = session.get(Channel, channel_id, options=(joinedload(Channel.account),))
        if not channel:
            flash("Канал не найден")
            return redirect(url_for("accounts_view"))
        if daily_cap is not None:
            channel.daily_cap = daily_cap
        channel.quiet_hours_start = quiet_start
        channel.quiet_hours_end = quiet_end
        channel.timezone = timezone
        channel.theme = theme
        session.add(channel)
    flash("Настройки канала обновлены")
    return redirect(url_for("accounts_view"))


if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8080)
