import io
import json
import os
import tempfile
from typing import Iterator
from unittest.mock import Mock

import pytest

pytest.importorskip("flask")
pytest.importorskip("sqlalchemy")


_DB_FD, _DB_PATH = tempfile.mkstemp(prefix="panel-test-", suffix=".db")
os.close(_DB_FD)
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_PATH}"

import panel.panel.app as app_module  # noqa: E402  # pylint: disable=wrong-import-position
from panel.panel.database import SessionLocal  # noqa: E402
from panel.panel.models import Account, Channel, Job, Link, Template  # noqa: E402


@pytest.fixture(autouse=True)
def _override_upload_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    upload_dir = tmp_path_factory.mktemp("uploads")
    original_upload_dir = app_module.UPLOAD_DIR
    app_module.UPLOAD_DIR = str(upload_dir)
    try:
        yield
    finally:
        app_module.UPLOAD_DIR = original_upload_dir


def teardown_module(_module) -> None:  # noqa: D401 - pytest hook
    if os.path.exists(_DB_PATH):
        os.remove(_DB_PATH)


def test_upload_stores_serializable_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module.schedule_pending_jobs, "delay", Mock())
    monkeypatch.setattr(app_module.trigger_ready_jobs, "delay", Mock())

    with SessionLocal() as session:
        account = Account(name="Test account", timezone="UTC")
        channel = Channel(name="Main", timezone="UTC", account=account)
        template = Template(
            name="Default",
            body="{{ greeting }} {{ extra }} {{ links.promo }}",
            default_context={"greeting": "Hello"},
        )
        link = Link(
            name="Promo",
            slug="promo",
            url="https://example.com",
            utm_params={"source": "test"},
        )
        session.add_all([account, channel, template, link])
        session.commit()
        channel_id = channel.id
        template_id = template.id

    client = app_module.app.test_client()
    with client:
        login_response = client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=True,
        )
        assert login_response.status_code == 200

        payload = {
            "channel_id": str(channel_id),
            "template_id": str(template_id),
            "title": "Video",
            "categoryId": "22",
            "template_context": json.dumps({"extra": "World", "tags": ["one", "two"]}),
        }
        payload["video"] = (io.BytesIO(b"content"), "video.mp4")
        response = client.post(
            "/upload",
            data=payload,
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert response.status_code == 302

    with SessionLocal() as session:
        job = session.query(Job).one()
        context = job.template_context

    # Контекст должен быть сериализуемым JSON
    json.dumps(context)
    assert context["greeting"] == "Hello"
    assert context["extra"] == "World"
    assert context["tags"] == ["one", "two"]
    assert isinstance(context["links"], dict)
    assert context["links"]["promo"]["url"] == "https://example.com"
    assert context["links"]["promo"]["utm"] == {"source": "test"}
    assert "utm" not in context  # функция не должна попадать в JSON
