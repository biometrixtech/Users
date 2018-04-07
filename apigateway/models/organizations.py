from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey
from db_connection import Base


class Organizations(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True) # uuid NOT NULL DEFAULT uuid_generate_v4(),
    name = Column(String) # character varying COLLATE pg_catalog."default",
    created_at = Column(DateTime) # timestamp without time zone NOT NULL,
    updated_at = Column(DateTime) # timestamp without time zone NOT NULL,
    address = Column(String) # character varying COLLATE pg_catalog."default",
    address_two = Column(String) # character varying COLLATE pg_catalog."default",
    city = Column(String) # character varying COLLATE pg_catalog."default",
    state = Column(String) # character varying COLLATE pg_catalog."default",
    zip = Column(String) # character varying COLLATE pg_catalog."default",
    team_count = Column(Integer) # integer,

"""
﻿    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    name character varying COLLATE pg_catalog."default",
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    address character varying COLLATE pg_catalog."default",
    address_two character varying COLLATE pg_catalog."default",
    city character varying COLLATE pg_catalog."default",
    state character varying COLLATE pg_catalog."default",
    zip character varying COLLATE pg_catalog."default",
    team_count integer,

"""