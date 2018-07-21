from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, ARRAY, text
from db_connection import Base
from sqlalchemy.dialects.postgresql.base import UUID


class Sport(Base):
    __tablename__ = 'sports'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    positions = Column(ARRAY(String()), server_default=text("'{}'::character varying[]"))
    active = Column(Boolean)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
