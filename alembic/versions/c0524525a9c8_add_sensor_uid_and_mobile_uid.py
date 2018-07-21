"""add sensor_uid and mobile_uid

Revision ID: c0524525a9c8
Revises: 283cc7e524ce
Create Date: 2018-07-21 11:37:35.818974

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c0524525a9c8'
down_revision = '283cc7e524ce'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('sensor_uid', sa.String))
    op.add_column('users', sa.Column('mobile_uid', sa.String))


def downgrade():
    op.drop_column('users', 'sensor_uid')
    op.drop_column('users', 'mobile_uid')
