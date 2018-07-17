from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum
from db_connection import Base
from .users import Users
from .training_groups import TrainingGroups


class TrainingSchedule(Base):
    __tablename__ = "training_schedule"

    id = Column(Integer)
    user_id = Column(String, ForeignKey(Users.id), primary_key=True)
    training_type = Column(Enum)  # Pratice, Competition, Strength and conditioning
    activity = Column(String)
    day_of_week = Column(String)
    duration_minutes = Column(Float)
    location = Column(String)