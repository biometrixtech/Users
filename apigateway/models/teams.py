from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey
from db_connection import Base
from .organizations import Organizations

class Teams(Base):
    __tablename__ = "teams"
    id = Column(String, primary_key=True)
    name = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    organization_id = Column(String, ForeignKey(Organizations.id))
    athlete_subscriptions = Column(Integer)
    athlete_manager_subscriptions = Column(Integer)
    gender = Column(Integer)
    sport_id = Column(String)

    #SQL Definition
    """
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    name character varying COLLATE pg_catalog."default",
    organization_id uuid,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    athlete_subscriptions integer,
    athlete_manager_subscriptions integer,
    gender integer,
    sport_id uuid,
    """
