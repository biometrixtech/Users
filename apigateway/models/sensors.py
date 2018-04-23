from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey
from db_connection import Base
from .teams import Teams
from .users import Users

class Sensors(Base):
    __tablename__ = "sensors"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    team_id = Column(String, ForeignKey(Teams.id))
    last_magnetometer_calibrated = Column(Boolean)
    last_user_id = Column(String, ForeignKey(Users.id))
    hw_model = Column(String)
    firmware_version = Column(String)
    clock_drift = Column(Integer)
    memory_level = Column(Float)

    # SQL Definition
    """
    id character varying COLLATE pg_catalog."default",
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    team_id uuid,
    last_magnetometer_calibrated boolean,
    last_user_id uuid,
    hw_model character varying COLLATE pg_catalog."default",
    firmware_version character varying COLLATE pg_catalog."default",
    clock_drift integer,
    memory_level double precision
    """