from config import POSTGRES_DB_URI
from sqlalchemy.orm.session import Session
from sqlalchemy.engine import create_engine
# from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import MetaData

engine = create_engine(POSTGRES_DB_URI, connect_args={'connect_timeout': 10})
# session = Session(bind=engine)
# base = declarative_base()

def load_user_class():

    metadata = MetaData()
    metadata.reflect(engine, only=['users'])

    AutoMapBase = automap_base(metadata=metadata)
    AutoMapBase.prepare(engine, reflect=True)
    Users = AutoMapBase.classes.users

    return Users

Users = load_user_class()
