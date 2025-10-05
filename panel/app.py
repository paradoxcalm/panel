import datetime as dt
import json
import os
from contextlib import contextmanager
from functools import wraps
from typing import Any, Dict, Iterable, List, Mapping, Optional
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
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
from sqlalchemy.orm import joinedload
from waitress import serve

from .constants import ACTIVE_JOB_STATUSES
from .database import DATA_DIR, SessionLocal, init_db
from .job_service import add_job_log, job_log_to_dict, job_to_dict
from .models import (
    Account,
    Channel,
    Job,
    Link,
    Role,
    ScheduleSlot,
    TagLibrary,
    Template,
    User,
)
from .rendering import TemplateRenderer, parse_context
from .scheduling import (
    SchedulerSettings,
    apply_channel_limits,
    find_slot_for_job,
    get_effective_timezone,
    load_channel_state,
)
from .tasks import schedule_pending_jobs, trigger_ready_jobs

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

MAX_TAGS = 15

template_renderer = TemplateRenderer()


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


def parse_time(value: str) -> Optional[dt.time]:
    if not value:
        return None
    try:
        return dt.time.fromisoformat(value)
    except ValueError:
        return None


def parse_json_mapping(raw: str, field_name: str) -> Dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Поле '{field_name}': некорректный JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Поле '{field_name}' должно быть JSON-объектом")
    return data


def parse_tag_list(raw: str) -> List[str]:
    if not raw:
        return []
    result: List[str] = []
    seen = set()
    for part in raw.replace("\n", ",").split(","):
        tag = part.strip()
        if not tag:
            continue
        low = tag.lower()
        if low in seen:
            continue
        seen.add(low)
        result.append(tag)
    return result


def merge_tags(*tag_groups: Iterable[str]) -> List[str]:
    seen = set()
    merged: List[str] = []
    for group in tag_groups:
        for tag in group:
            norm = tag.strip()
            if not norm:
                continue
            low = norm.lower()
            if low in seen:
                continue
            if len(merged) >= MAX_TAGS:
                return merged
            seen.add(low)
            merged.append(norm)
    return merged


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
        templates: List[Template] = []
        quick_tags: List[TagLibrary] = []
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
            templates = (
                session.query(Template)
                .filter(Template.is_active.is_(True), Template.type == "description")
                .order_by(Template.name)
                .all()
            )
            quick_tags = (
                session.query(TagLibrary)
                .filter(TagLibrary.is_active.is_(True))
                .order_by(TagLibrary.category, TagLibrary.tag)
                .all()
            )
        return render_template(
            "index.html",
            account=account,
            channels=channels,
            queue=queue,
            templates=templates,
            quick_tags=quick_tags,
            MAX_TAGS=MAX_TAGS,
        )
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
        category_id = request.form.get("categoryId") or "22"
        mode = request.form.get("mode")
        template_id = request.form.get("template_id", type=int)
        if not template_id:
            flash("Выберите шаблон описания")
            return redirect(url_for("index"))
        template = session.get(Template, template_id)
        if not template or not template.is_active:
            flash("Шаблон недоступен")
            return redirect(url_for("index"))
        context_raw = request.form.get("template_context") or ""
        try:
            context_overrides = parse_context(context_raw)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("index"))

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
            publish_at_utc = None
        else:
            publish_at_utc = dt.datetime.now(dt.timezone.utc)

        if publish_at_utc:
            publish_at_utc = apply_channel_limits(session, channel, publish_at_utc)

        links = session.query(Link).filter(Link.is_active.is_(True)).all()
        try:
            render_result = template_renderer.render(
                template,
                context=context_overrides,
                links=links,
                apply_spintax=True,
            )
            description = render_result.text
        except Exception as exc:
            app.logger.exception("Не удалось отрендерить шаблон %s", template_id)
            flash(f"Ошибка рендера шаблона: {exc}")
            return redirect(url_for("index"))

        template_tags = template.default_tags or []
        context_tags: List[str] = []
        ctx_value = render_result.context.get("tags")
        if isinstance(ctx_value, list):
            context_tags = [str(item) for item in ctx_value if str(item).strip()]

        selected_tag_ids = [
            int(tag_id)
            for tag_id in (request.form.getlist("tag_ids") or [])
            if tag_id.isdigit()
        ]
        quick_tag_values: List[str] = []
        if selected_tag_ids:
            quick_tag_values = [
                tag.tag
                for tag in session.query(TagLibrary)
                .filter(TagLibrary.id.in_(selected_tag_ids))
                .filter(TagLibrary.is_active.is_(True))
                .all()
            ]
        custom_tags = parse_tag_list(request.form.get("custom_tags") or "")
        candidate_total = (
            len(template_tags)
            + len(context_tags)
            + len(quick_tag_values)
            + len(custom_tags)
        )
        tags = merge_tags(template_tags, context_tags, quick_tag_values, custom_tags)
        if not tags:
            tags = ["youtube", "shorts"]
        elif candidate_total > MAX_TAGS and len(tags) == MAX_TAGS:
            flash(f"Список тегов ограничен {MAX_TAGS} значениями")
        status = "queued"
        if publish_at_utc:
            status = "scheduled"
        job = Job(
            channel_id=channel.id,
            title=title,
            description=description,
            tags=tags or ["youtube", "shorts"],
            category_id=category_id,
            publish_at=publish_at_utc,
            video_path=video_path,
            thumb_path=thumb_path,
            status=status,
            template_id=template.id,
            template_context=render_result.serializable_context,
        )
        job.channel = channel
        session.add(job)
        session.flush()
        add_job_log(
            session,
            job,
            "job.created",
            payload={
                "mode": mode or "now",
                "status": status,
                "publish_at": publish_at_utc.isoformat() if publish_at_utc else None,
            },
        )
        if publish_at_utc:
            slot = ScheduleSlot(
                channel_id=channel.id,
                job_id=job.id,
                scheduled_for=publish_at_utc,
                status="reserved",
            )
            session.add(slot)
        session.commit()
        flash("Добавлено в очередь")
    finally:
        session.close()

    if publish_at_utc:
        if publish_at_utc <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            trigger_ready_jobs.delay()
    else:
        schedule_pending_jobs.delay()
    return redirect(url_for("index"))


@app.route("/templates", methods=["GET"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def templates_view():
    session = SessionLocal()
    try:
        templates = session.query(Template).order_by(Template.name).all()
        tags = session.query(TagLibrary).order_by(TagLibrary.category, TagLibrary.tag).all()
        return render_template("templates_manage.html", templates=templates, tags=tags)
    finally:
        session.close()


def _fill_template_from_form(template: Template, form) -> None:
    template.name = (form.get("name") or "").strip()
    template.slug = (form.get("slug") or "").strip() or None
    template.type = (form.get("type") or "description").strip() or "description"
    template.body = (form.get("body") or "").strip()
    template.platform = (form.get("platform") or "").strip() or None
    template.is_active = bool(form.get("is_active"))
    template.utm_sets = parse_json_mapping(form.get("utm_sets"), "UTM-наборы")
    template.default_context = parse_json_mapping(
        form.get("default_context"), "Контекст по умолчанию"
    )
    template.default_tags = parse_tag_list(form.get("default_tags"))
    template.topics = parse_tag_list(form.get("topics"))
    if not template.name:
        raise ValueError("Название шаблона обязательно")
    if not template.body:
        raise ValueError("Тело шаблона не может быть пустым")


@app.route("/templates", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def templates_create():
    session = SessionLocal()
    try:
        template = Template()
        try:
            _fill_template_from_form(template, request.form)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("templates_view"))
        session.add(template)
        session.commit()
        flash("Шаблон создан")
    except Exception as exc:
        session.rollback()
        flash(f"Не удалось создать шаблон: {exc}")
    finally:
        session.close()
    return redirect(url_for("templates_view"))


@app.route("/templates/<int:template_id>", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def templates_update(template_id: int):
    action = request.form.get("action") or "update"
    session = SessionLocal()
    try:
        template = session.get(Template, template_id)
        if not template:
            flash("Шаблон не найден")
            return redirect(url_for("templates_view"))
        if action == "delete":
            session.delete(template)
            try:
                session.commit()
            except Exception as exc:
                session.rollback()
                flash(f"Не удалось удалить шаблон: {exc}")
                return redirect(url_for("templates_view"))
            flash("Шаблон удалён")
            return redirect(url_for("templates_view"))
        try:
            _fill_template_from_form(template, request.form)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("templates_view"))
        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            flash(f"Не удалось обновить шаблон: {exc}")
            return redirect(url_for("templates_view"))
        flash("Шаблон обновлён")
    finally:
        session.close()
    return redirect(url_for("templates_view"))


@app.route("/templates/render", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def templates_render():
    payload = request.get_json(silent=True) or {}
    template_id = payload.get("template_id")
    if not template_id:
        return jsonify({"ok": False, "error": "template_id обязателен"}), 400
    try:
        template_id = int(template_id)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Некорректный template_id"}), 400
    apply_spintax = bool(payload.get("apply_spintax"))
    context_payload = payload.get("context")
    context_data: Dict[str, Any]
    try:
        if isinstance(context_payload, str):
            context_data = parse_context(context_payload)
        elif isinstance(context_payload, dict):
            context_data = context_payload
        else:
            context_data = {}
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    session = SessionLocal()
    try:
        template = session.get(Template, template_id)
        if not template:
            return jsonify({"ok": False, "error": "Шаблон не найден"}), 404
        links = session.query(Link).filter(Link.is_active.is_(True)).all()
        try:
            result = template_renderer.render(
                template,
                context=context_data,
                links=links,
                apply_spintax=apply_spintax,
            )
        except Exception as exc:
            app.logger.exception("Ошибка рендера шаблона %s", template_id)
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "rendered": result.text})
    finally:
        session.close()


@app.route("/links", methods=["GET"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def links_view():
    session = SessionLocal()
    try:
        links = session.query(Link).order_by(Link.name).all()
        return render_template("links_manage.html", links=links)
    finally:
        session.close()


def _fill_link_from_form(link: Link, form) -> None:
    link.name = (form.get("name") or "").strip()
    link.slug = (form.get("slug") or "").strip()
    link.url = (form.get("url") or "").strip()
    link.description = (form.get("description") or "").strip() or None
    link.platform = (form.get("platform") or "").strip() or None
    link.is_active = bool(form.get("is_active"))
    link.utm_params = parse_json_mapping(form.get("utm_params"), "UTM")
    link.metadata = parse_json_mapping(form.get("metadata"), "Доп. данные")
    if not link.name:
        raise ValueError("Название ссылки обязательно")
    if not link.slug:
        raise ValueError("Slug обязателен")
    if not link.url:
        raise ValueError("URL обязателен")


@app.route("/links", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def links_create():
    session = SessionLocal()
    try:
        link = Link()
        try:
            _fill_link_from_form(link, request.form)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("links_view"))
        session.add(link)
        session.commit()
        flash("Ссылка добавлена")
    except Exception as exc:
        session.rollback()
        flash(f"Не удалось сохранить ссылку: {exc}")
    finally:
        session.close()
    return redirect(url_for("links_view"))


@app.route("/links/<int:link_id>", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def links_update(link_id: int):
    action = request.form.get("action") or "update"
    session = SessionLocal()
    try:
        link = session.get(Link, link_id)
        if not link:
            flash("Ссылка не найдена")
            return redirect(url_for("links_view"))
        if action == "delete":
            session.delete(link)
            try:
                session.commit()
            except Exception as exc:
                session.rollback()
                flash(f"Не удалось удалить ссылку: {exc}")
                return redirect(url_for("links_view"))
            flash("Ссылка удалена")
            return redirect(url_for("links_view"))
        if action == "toggle":
            link.is_active = not link.is_active
            try:
                session.commit()
            except Exception as exc:
                session.rollback()
                flash(f"Не удалось изменить статус: {exc}")
                return redirect(url_for("links_view"))
            flash("Статус ссылки обновлён")
            return redirect(url_for("links_view"))
        try:
            _fill_link_from_form(link, request.form)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("links_view"))
        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            flash(f"Не удалось обновить ссылку: {exc}")
            return redirect(url_for("links_view"))
        flash("Ссылка обновлена")
    finally:
        session.close()
    return redirect(url_for("links_view"))


@app.route("/tags", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def tags_create():
    session = SessionLocal()
    try:
        tag = TagLibrary(
            tag=(request.form.get("tag") or "").strip(),
            category=(request.form.get("category") or "").strip() or None,
            is_active=bool(request.form.get("is_active")),
        )
        if not tag.tag:
            flash("Тег не может быть пустым")
            return redirect(url_for("templates_view"))
        session.add(tag)
        session.commit()
        flash("Тег добавлен")
    except Exception as exc:
        session.rollback()
        flash(f"Не удалось добавить тег: {exc}")
    finally:
        session.close()
    return redirect(url_for("templates_view"))


@app.route("/tags/<int:tag_id>", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def tags_update(tag_id: int):
    action = request.form.get("action") or "update"
    session = SessionLocal()
    try:
        tag = session.get(TagLibrary, tag_id)
        if not tag:
            flash("Тег не найден")
            return redirect(url_for("templates_view"))
        if action == "delete":
            session.delete(tag)
            try:
                session.commit()
            except Exception as exc:
                session.rollback()
                flash(f"Не удалось удалить тег: {exc}")
                return redirect(url_for("templates_view"))
            flash("Тег удалён")
            return redirect(url_for("templates_view"))
        if action == "toggle":
            tag.is_active = not tag.is_active
            try:
                session.commit()
            except Exception as exc:
                session.rollback()
                flash(f"Не удалось изменить статус тега: {exc}")
                return redirect(url_for("templates_view"))
            flash("Статус тега обновлён")
            return redirect(url_for("templates_view"))
        tag.tag = (request.form.get("tag") or "").strip()
        tag.category = (request.form.get("category") or "").strip() or None
        tag.is_active = bool(request.form.get("is_active"))
        if not tag.tag:
            flash("Тег не может быть пустым")
            return redirect(url_for("templates_view"))
        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            flash(f"Не удалось обновить тег: {exc}")
            return redirect(url_for("templates_view"))
        flash("Тег обновлён")
    finally:
        session.close()
    return redirect(url_for("templates_view"))


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
    schedule_pending_jobs.delay()
    trigger_ready_jobs.delay()
    flash("Запущены фоновые задания на планирование и загрузку")
    return redirect(url_for("index"))


@app.route("/api/jobs", methods=["GET"])
@roles_required(ROLE_VIEWER, ROLE_EDITOR, ROLE_OWNER)
def api_jobs_list():
    session = SessionLocal()
    try:
        account = ensure_active_account(session)
        query = (
            session.query(Job)
            .options(joinedload(Job.channel), joinedload(Job.schedule_slot))
            .order_by(Job.created_at.desc())
        )
        if account:
            query = query.join(Channel).filter(Channel.account_id == account.id)
        jobs = query.all()
        data = [job_to_dict(job) for job in jobs]
        return jsonify({"jobs": data})
    finally:
        session.close()


@app.route("/api/jobs", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def api_jobs_create():
    payload = request.get_json(silent=True) or {}
    channel_id = payload.get("channel_id")
    if not channel_id:
        return jsonify({"error": "channel_id обязателен"}), 400
    session = SessionLocal()
    try:
        channel = session.get(Channel, int(channel_id), options=(joinedload(Channel.account),))
        if not channel:
            return jsonify({"error": "Канал не найден"}), 404
        template_id = payload.get("template_id")
        template = None
        if template_id:
            template = session.get(Template, int(template_id))
            if not template:
                return jsonify({"error": "Шаблон не найден"}), 404
        publish_at_utc: Optional[dt.datetime] = None
        publish_raw = payload.get("publish_at")
        if publish_raw:
            try:
                parsed = dt.datetime.fromisoformat(publish_raw)
            except ValueError:
                return jsonify({"error": "Некорректный формат publish_at"}), 400
            tz = ZoneInfo(get_effective_timezone(channel))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=tz)
            else:
                parsed = parsed.astimezone(tz)
            publish_at_utc = parsed.astimezone(dt.timezone.utc)
        title = (payload.get("title") or "").strip()
        if not title:
            return jsonify({"error": "title обязателен"}), 400
        video_path = payload.get("video_path")
        if not video_path:
            return jsonify({"error": "video_path обязателен"}), 400
        description = payload.get("description") or ""
        thumb_path = payload.get("thumb_path")
        tags_value = payload.get("tags") or []
        if isinstance(tags_value, str):
            tags = parse_tag_list(tags_value)
        else:
            tags = [str(tag) for tag in tags_value]
        template_context = payload.get("template_context") or {}
        if isinstance(template_context, str):
            try:
                template_context = json.loads(template_context)
            except json.JSONDecodeError:
                template_context = {}
        if isinstance(template_context, Mapping):
            template_context = template_renderer.make_serializable_context(template_context)
        category_id = str(payload.get("category_id") or "22")
        status = "scheduled" if publish_at_utc else "queued"
        if publish_at_utc:
            publish_at_utc = apply_channel_limits(session, channel, publish_at_utc)
        job = Job(
            channel_id=channel.id,
            title=title,
            description=description,
            tags=tags,
            category_id=category_id,
            publish_at=publish_at_utc,
            video_path=video_path,
            thumb_path=thumb_path,
            status=status,
            template_id=template.id if template else None,
            template_context=template_context if isinstance(template_context, dict) else {},
        )
        job.channel = channel
        session.add(job)
        session.flush()
        add_job_log(
            session,
            job,
            "job.created.api",
            payload={
                "status": status,
                "publish_at": publish_at_utc.isoformat() if publish_at_utc else None,
            },
        )
        if publish_at_utc:
            session.add(
                ScheduleSlot(
                    channel_id=channel.id,
                    job_id=job.id,
                    scheduled_for=publish_at_utc,
                    status="reserved",
                )
            )
        session.commit()
        job_dict = job_to_dict(job)
    finally:
        session.close()

    if publish_at_utc:
        trigger_ready_jobs.delay()
    else:
        schedule_pending_jobs.delay()
    return jsonify({"job": job_dict}), 201


@app.route("/api/jobs/<int:job_id>/retry", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def api_job_retry(job_id: int):
    session = SessionLocal()
    try:
        job = session.get(
            Job,
            job_id,
            options=(joinedload(Job.schedule_slot), joinedload(Job.channel)),
        )
        if not job:
            return jsonify({"error": "Задание не найдено"}), 404
        if job.schedule_slot:
            session.delete(job.schedule_slot)
        job.publish_at = None
        job.status = "queued"
        job.started_at = None
        job.completed_at = None
        job.error_message = None
        job.youtube_video_id = None
        job.celery_task_id = None
        add_job_log(session, job, "job.retry")
        session.flush()
        job_dict = job_to_dict(job)
        session.commit()
    finally:
        session.close()
    schedule_pending_jobs.delay()
    return jsonify({"job": job_dict})


@app.route("/api/jobs/<int:job_id>/logs", methods=["GET"])
@roles_required(ROLE_VIEWER, ROLE_EDITOR, ROLE_OWNER)
def api_job_logs(job_id: int):
    session = SessionLocal()
    try:
        job = session.get(Job, job_id, options=(joinedload(Job.logs),))
        if not job:
            return jsonify({"error": "Задание не найдено"}), 404
        data = [job_log_to_dict(entry) for entry in job.logs]
        return jsonify({"logs": data})
    finally:
        session.close()


@app.route("/api/schedule", methods=["POST"])
@roles_required(ROLE_EDITOR, ROLE_OWNER)
def api_schedule_update():
    payload = request.get_json(silent=True) or {}
    job_id = payload.get("job_id")
    if not job_id:
        return jsonify({"error": "job_id обязателен"}), 400
    scheduled_raw = payload.get("scheduled_for")
    session = SessionLocal()
    try:
        job = session.get(
            Job,
            int(job_id),
            options=(
                joinedload(Job.channel).joinedload("account"),
                joinedload(Job.schedule_slot),
            ),
        )
        if not job:
            return jsonify({"error": "Задание не найдено"}), 404
        channel = job.channel
        if not channel:
            return jsonify({"error": "Канал недоступен"}), 400
        tz = ZoneInfo(get_effective_timezone(channel))
        job_dict: Dict[str, Any]
        if not scheduled_raw:
            if job.schedule_slot:
                session.delete(job.schedule_slot)
            job.publish_at = None
            job.status = "queued"
            job.started_at = None
            job.completed_at = None
            job.celery_task_id = None
            add_job_log(session, job, "scheduler.manual-reset")
            session.flush()
            job_dict = job_to_dict(job)
            session.commit()
            next_action = "queue"
        else:
            parsed: Optional[dt.datetime]
            if isinstance(scheduled_raw, dict):
                date_part = scheduled_raw.get("date")
                time_part = scheduled_raw.get("time")
                if not date_part or not time_part:
                    return jsonify({"error": "Нужно указать дату и время"}), 400
                try:
                    parsed = dt.datetime.fromisoformat(f"{date_part}T{time_part}")
                except ValueError:
                    return jsonify({"error": "Некорректный формат даты"}), 400
            else:
                try:
                    parsed = dt.datetime.fromisoformat(str(scheduled_raw))
                except ValueError:
                    return jsonify({"error": "Некорректный формат даты"}), 400
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=tz)
            else:
                parsed = parsed.astimezone(tz)
            desired_utc = parsed.astimezone(dt.timezone.utc)
            state = load_channel_state(session, channel, exclude_job_id=job.id)
            settings = SchedulerSettings.from_env()
            slot_time = find_slot_for_job(
                session,
                job,
                desired_utc=desired_utc,
                occupied=state.occupied,
                extra_counts=state.extra_counts,
                settings=settings,
            )
            if slot_time is None:
                return jsonify({"error": "Не удалось подобрать слот"}), 409
            job.publish_at = slot_time
            job.status = "scheduled"
            job.started_at = None
            job.completed_at = None
            job.celery_task_id = None
            if job.schedule_slot:
                job.schedule_slot.scheduled_for = slot_time
                job.schedule_slot.status = "reserved"
            else:
                session.add(
                    ScheduleSlot(
                        channel_id=channel.id,
                        job_id=job.id,
                        scheduled_for=slot_time,
                        status="reserved",
                    )
                )
            add_job_log(
                session,
                job,
                "scheduler.manual-set",
                payload={"scheduled_for": slot_time.isoformat()},
            )
            state.register(channel, slot_time)
            session.flush()
            job_dict = job_to_dict(job)
            session.commit()
            next_action = "trigger"
    finally:
        session.close()

    if scheduled_raw and next_action == "trigger":
        publish_iso = job_dict.get("publish_at") if isinstance(job_dict, dict) else None
        if publish_iso:
            try:
                publish_dt = dt.datetime.fromisoformat(str(publish_iso))
            except ValueError:
                publish_dt = None
        else:
            publish_dt = None
        if publish_dt and publish_dt <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            trigger_ready_jobs.delay()
        else:
            schedule_pending_jobs.delay()
    else:
        schedule_pending_jobs.delay()
    return jsonify({"job": job_dict})


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
