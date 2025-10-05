import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

def _default_database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    return f"sqlite:///{os.path.join(DATA_DIR, 'app.db')}"

DATABASE_URL = _default_database_url()
engine = create_engine(DATABASE_URL, future=True, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
Base = declarative_base()


def init_db():
    from . import models  # noqa: F401 - ensure models imported
    Base.metadata.create_all(bind=engine)
