from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, text
from sqlalchemy.dialects.postgresql.base import UUID
from db_connection import Base
from models._types import EnumTypeBase
from .sports import Sport


class SportPosition(Base):
    __tablename__ = "sports_positions"

    id = Column(String, primary_key=True)
    sport_id = Column(String, ForeignKey(Sport.id))
    name = Column(String)
    value = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
