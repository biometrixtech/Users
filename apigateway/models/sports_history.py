from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, text
from sqlalchemy.dialects.postgresql.base import UUID
from db_connection import Base
from models._types import EnumTypeBase
from .users import Users
# from .competition_level import CompetitionLevel

class CompetitionEnumType(EnumTypeBase):
    name_values = {
        'recreational_challenge': 0, # Recreational / Challenge,
        'high_school': 1, # High School,
        'club_travel': 2, # Club / Travel
        'development_league': 3, # Development League,
        'ncaa_division_i': 4, # NCAA Division I,
        'ncaa_division_ii': 5, # NCAA Division II,
        'ncaa_division_iii': 6, # NCAA Division III,
        'professional': 7 # Professional
    }


class SportHistory(Base):
    __tablename__ = "sports_history"

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    user_id = Column(UUID, ForeignKey(Users.id))
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    position = Column(String)
    # competition_level = Column(String, ForeignKey(CompetitionLevel.id)) # TODO
    competiton_level = Column(CompetitionEnumType)
    start_date = Column(DateTime)
    end_date = Column(DateTime)

    # seasons_id = Column(Integer, ForeignKey(Seasons.id))