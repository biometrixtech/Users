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
    op.alter_column('users', 'sensor_uid', new_column_name='sensor_pid')
    op.alter_column('users', 'mobile_uid', new_column_name='mobile_udid')


def downgrade():
    op.alter_column('users', 'sensor_pid', new_column_name='sensor_uid')
    op.alter_column('users', 'mobile_udid', new_column_name='mobile_uid')
