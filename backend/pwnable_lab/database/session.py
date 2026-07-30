"""세션/엔진 팩토리."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pwnable_lab.database.models import Base


def make_engine(database_url: str, *, create_schema: bool = True):
    kwargs: dict = {"future": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        # 인메모리 DB 는 커넥션마다 별도이므로 단일 커넥션 풀로 공유한다.
        if ":memory:" in database_url or database_url in ("sqlite://",):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    if create_schema:
        Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
