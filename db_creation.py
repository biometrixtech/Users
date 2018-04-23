import models
from db_connection import engine, Base


# inside of a "create the database" script, first create
# tables:
metadata = Base.metadata
metadata.create_all(engine)

# then, load the Alembic configuration and generate the
# version table, "stamping" it with the most recent rev:
from alembic.config import Config
from alembic import command
#alembic_cfg = Config("alembic.ini")
#command.stamp(alembic_cfg, "head")
print(metadata)
