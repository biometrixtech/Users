from config import POSTGRES_DB_URI
from sqlalchemy.orm.session import Session
from sqlalchemy.engine import create_engine
# from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import MetaData

engine = create_engine(POSTGRES_DB_URI, connect_args={'connect_timeout': 10})
# session = Session(bind=engine)
# base = declarative_base()


def define_auto_map_base():
    metadata = MetaData()
    metadata.reflect(engine, only=['users', 'teams', 'sensors', ''])

    AutoMapBase = automap_base(metadata=metadata)
    AutoMapBase.prepare(engine, reflect=True)
    return AutoMapBase


def load_table_classes(AutoMapBase):
    Users = AutoMapBase.classes.users
    Teams = AutoMapBase.classes.teams
    Sensors = AutoMapBase.classes.sensors
    return Users, Teams, Sensors


Users, Teams, Sensors = load_table_classes(define_auto_map_base())
