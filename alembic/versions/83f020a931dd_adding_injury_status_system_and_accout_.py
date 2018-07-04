"""Adding injury status system and account type to users

Revision ID: 83f020a931dd
Revises: 896ac863b8b7
Create Date: 2018-07-02 21:42:44.239871

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '83f020a931dd'
down_revision = '13a7699e493e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('account_type', sa.Integer))
    op.add_column('users', sa.Column('account_status', sa.Integer))
    op.add_column('users', sa.Column('system_type', sa.Integer))
    op.add_column('users', sa.Column('injury_status', sa.Integer))


def downgrade():
    op.drop_column('users', 'account_type')
    op.drop_column('users', 'account_status')
    op.drop_column('users', 'system_type')
    op.drop_column('users', 'injury_status')
