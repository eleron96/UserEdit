from contextlib import asynccontextmanager

from decouple import config
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase


class BaseDBModel(DeclarativeBase):
    pass


DATABASE_URL = config('DATABASE_URL', default='your_default_database_url')
engine = create_async_engine(DATABASE_URL)
async_session = async_sessionmaker(bind=engine)


@asynccontextmanager
async def get_session():
    session = async_session()
    try:
        yield session
        await session.commit()
    except Exception as e:
        await session.rollback()
        raise e
    finally:
        await session.close()
