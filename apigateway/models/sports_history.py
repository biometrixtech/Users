from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, text
from sqlalchemy.dialects.postgresql.base import UUID
from db_connection import Base
from models._types import EnumTypeBase
from .users import Users


class CompetitionEnumType(EnumTypeBase):
    name_values = {
        # Recreational / Challenge,
        # High School,
        # Club / Travel
        # Development League,
        # NCAA Division III,
        # NCAA Division II,
        # NCAA Division I,
        # Professional

    }


class SportHistory(Base):
    __tablename__ = "sports_history"

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    user_id = Column(String, ForeignKey(Users.id))
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    competition_level = Column(Enum) # TODO
    start_date = Column(DateTime)
    end_date = Column(DateTime)

    # seasons_id = Column(Integer, ForeignKey(Seasons.id))