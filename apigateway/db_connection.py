from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import MetaData
import os


engine = create_engine(os.environ['POSTGRES_DB_URI'], connect_args={'connect_timeout': 10})
# session = Session(bind=engine)
Base = declarative_base()


def define_auto_map_base():
    metadata = MetaData()
    metadata.reflect(engine, only=['users', 'teams', 'teams_users', 'organizations', 'sensors'])

    AutoMapBase = automap_base(metadata=metadata)
    AutoMapBase.prepare(engine, reflect=True)
    return AutoMapBase
