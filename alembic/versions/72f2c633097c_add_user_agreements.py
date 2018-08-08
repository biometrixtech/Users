"""add_user_agreements

Revision ID: 72f2c633097c
Revises: af901a11a396
Create Date: 2018-08-06 18:53:39.630564

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '72f2c633097c'
down_revision = 'af901a11a396'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('agreed_terms_of_use', sa.Boolean))
    op.add_column('users', sa.Column('agreed_privacy_policy', sa.Boolean))
    op.add_column('users', sa.Column('cleared_to_play', sa.Boolean))


def downgrade():
    op.drop_column('users', 'agreed_terms_of_use')
    op.drop_column('users', 'agreed_privacy_policy')
    op.drop_column('users', 'cleared_to_play')
