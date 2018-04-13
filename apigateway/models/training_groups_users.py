from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum
from db_connection import Base
from .users import Users
from .training_groups import TrainingGroups


class TrainingGroupsUsers(Base):
    __tablename__ = "training_groups_users"

    training_group_id = Column(String, ForeignKey(TrainingGroups.id), primary_key=True)
    user_id = Column(String, ForeignKey(Users.id), primary_key=True)
