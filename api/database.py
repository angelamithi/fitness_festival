"""
Database setup — SQLAlchemy async with PostgreSQL
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, DateTime, func
from dotenv import load_dotenv

load_dotenv()

# Render provides DATABASE_URL as a postgres:// URL — asyncpg needs postgresql+asyncpg://
_raw_url = os.getenv("DATABASE_URL", "")
if _raw_url.startswith("postgres://"):
    _raw_url = _raw_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif _raw_url.startswith("postgresql://"):
    _raw_url = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)

DATABASE_URL = _raw_url or "postgresql+asyncpg://localhost/fitness_festival"

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Order(Base):
    """Stores every ticket purchase attempt."""
    __tablename__ = "orders"

    order_id            = Column(String, primary_key=True)
    ticket_id           = Column(String, nullable=False, index=True)
    name                = Column(String, nullable=False)
    phone               = Column(String, nullable=False)
    email               = Column(String, nullable=False)
    amount              = Column(Integer, nullable=False)
    ticket_type         = Column(String, nullable=False, default="standard")
    status              = Column(String, nullable=False, default="pending")
    checkout_request_id = Column(String, nullable=True)
    mpesa_ref           = Column(String, nullable=True)
    failure_reason      = Column(String, nullable=True)
    paid_at             = Column(DateTime(timezone=True), nullable=True)
    amount_paid         = Column(Integer, nullable=True)
    created_at          = Column(DateTime(timezone=True), server_default=func.now())


class CheckIn(Base):
    """
    Tracks gate check-in status for each INDIVIDUAL ticket.
    Bulk orders store multiple ticket IDs comma-separated on one Order row,
    but each ticket within that order needs to be checked in separately —
    so each gets its own row here, keyed by its own unique ticket_id.
    """
    __tablename__ = "checkins"

    ticket_id     = Column(String, primary_key=True)   # e.g. "TKT-AB12CD"
    order_id      = Column(String, nullable=False, index=True)
    name          = Column(String, nullable=False)
    ticket_type   = Column(String, nullable=False, default="standard")
    checked_in_at = Column(DateTime(timezone=True), server_default=func.now())


async def init_db():
    """Create tables if they don't exist (runs on startup)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        yield session