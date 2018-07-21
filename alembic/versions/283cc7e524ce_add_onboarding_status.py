"""Add onboarding_status

Revision ID: 283cc7e524ce
Revises: 83f020a931dd
Create Date: 2018-07-11 19:59:38.620391

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '283cc7e524ce'
down_revision = '83f020a931dd'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('onboarding_status', sa.ARRAY(sa.String)))
    # op.add_column('users', sa.Column('account_type', sa.Integer))

def downgrade():
    op.drop_column('users', 'onboarding_status')
