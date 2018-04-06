from config import POSTGRES_DB_URI
from sqlalchemy.orm.session import Session
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import MetaData

engine = create_engine(POSTGRES_DB_URI, connect_args={'connect_timeout': 10})
# session = Session(bind=engine)
Base = declarative_base()


def define_auto_map_base():
    metadata = MetaData()
    metadata.reflect(engine, only=['users', 'teams', 'teams_users', 'organizations', 'sensors'])

    AutoMapBase = automap_base(metadata=metadata)
    AutoMapBase.prepare(engine, reflect=True)
    return AutoMapBase


def load_table_classes(AutoMapBase):
    Users = AutoMapBase.classes.users
    #Teams = AutoMapBase.classes.teams
    Organization = AutoMapBase.classes.organizations
    return Users, Organization

AutoMapBase = define_auto_map_base()
#TeamsUsers = AutoMapBase.classes.teams_users
Users, Organization = load_table_classes(AutoMapBase)


class Teams(Base):
    __tablename__ = "teams"
    id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    organization_id = Column(String, ForeignKey(Organization.id))
    athlete_subscriptions = Column(Integer)
    athlete_manager_subscriptions = Column(Integer)
    gender = Column(Integer)
    sport_id = Column(String)



class TeamsUsers(Base):
    __tablename__ = "teams_users"

    team_id = Column(String, ForeignKey(Teams.id), primary_key=True)
    user_id = Column(String, ForeignKey(Users.id), primary_key=True)


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