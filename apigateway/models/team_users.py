import enum
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum
from db_connection import Base
from .teams import Teams
from .users import Users

class TeamsUsers(Base):
    __tablename__ = "teams_users"

    team_id = Column(String, ForeignKey(Teams.id), primary_key=True)
    user_id = Column(String, ForeignKey(Users.id), primary_key=True)
