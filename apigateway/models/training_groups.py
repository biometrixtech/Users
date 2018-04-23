from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey
from db_connection import Base
from .users import Users
from .team_users import Teams


class TrainingGroups(Base):
    __tablename__ = "training_groups"

    id = Column(String, primary_key=True) # uuid NOT NULL DEFAULT uuid_generate_v4(),
    team_id = Column(String, ForeignKey(Teams.id)) # uuid,
    user_id = Column(String, ForeignKey(Users.id)) # uuid,
    created_at = Column(DateTime) # timestamp without time zone NOT NULL,
    updated_at = Column(DateTime) # timestamp without time zone NOT NULL,
    name = Column(String) # character varying COLLATE pg_catalog."default",
    description = Column(String) # character varying COLLATE pg_catalog."default",
    active = Column(Boolean) # boolean DEFAULT true,
    tier = Column(Integer) # integer,
    manager_id = Column(String) # uuid,


"""
﻿    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    team_id uuid,
    user_id uuid,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    name character varying COLLATE pg_catalog."default",
    description character varying COLLATE pg_catalog."default",
    active boolean DEFAULT true,
    tier integer,
    manager_id uuid,
"""