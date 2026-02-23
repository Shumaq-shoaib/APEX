"""add error_message to dynamic_test_session

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-02-23 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('dynamic_test_session', sa.Column('error_message', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('dynamic_test_session', 'error_message')
