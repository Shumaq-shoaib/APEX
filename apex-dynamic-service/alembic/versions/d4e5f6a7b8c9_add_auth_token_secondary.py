"""add auth_token_secondary to dynamic_test_session

Revision ID: d4e5f6a7b8c9
Revises: 2fab52643c85
Create Date: 2025-12-09 01:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4e5f6a7b8c9'
down_revision = '5af2645ff1f7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('dynamic_test_session', sa.Column('auth_token_secondary', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('dynamic_test_session', 'auth_token_secondary')
