from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, text
from sqlalchemy.dialects.postgresql.base import UUID
from db_connection import Base


class CompetitionLevel(Base):
    __tablename__ = "competition_level"

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    label = Column(String)
    value = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
