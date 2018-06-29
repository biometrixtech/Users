"""add_athlete_connections_table

Revision ID: 896ac863b8b7
Revises: 13a7699e493e
Create Date: 2018-05-19 15:15:02.811992

"""
from alembic import op
import sqlalchemy as sa
from models.users import Users
from models.athlete_permissions import AccessLevelEnumType


# revision identifiers, used by Alembic.
revision = '896ac863b8b7'
down_revision = '13a7699e493e'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('athlete_permissions')
    op.add_column('athlete_permissions', sa.Column('athlete_user_id', sa.ForeignKey(Users.id)))
    op.add_column('athlete_permissions', sa.Column('user_id', sa.ForeignKey(Users.id)))
    op.add_column('athlete_permissions', sa.Column('role_access_level', AccessLevelEnumType))


def downgrade():
    op.drop_table('athlete_permissions')
