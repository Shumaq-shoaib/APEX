"""add enable_crawl to dynamic_test_session

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-03-23 01:48:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('dynamic_test_session', sa.Column('enable_crawl', sa.String(10), server_default='false', nullable=True))


def downgrade() -> None:
    op.drop_column('dynamic_test_session', 'enable_crawl')
