"""rename_sensor_and_mobile_ids

Revision ID: af901a11a396
Revises: c0524525a9c8
Create Date: 2018-07-25 22:31:32.354209

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'af901a11a396'
down_revision = 'c0524525a9c8'
branch_labels = None
depends_on = None


def upgrade(): # TODO: Look up how to rename a column
    op.add_column('users', sa.Column('sensor_pid', sa.String))
    op.add_column('users', sa.Column('mobile_uuid', sa.String))


def downgrade():
    op.drop_column('users', 'sensor_pid')
    op.drop_column('users', 'mobile_uuid')

