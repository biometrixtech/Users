"""Add zip_code

Revision ID: 13a7699e493e
Revises: 
Create Date: 2018-04-23 17:14:00.167210

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '13a7699e493e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('zip_code', sa.String))


def downgrade():
    op.drop_column('users', 'zip_code')
