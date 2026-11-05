"""agent platform and profile (reported by the Go agent at enrollment)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-05 13:05:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('platform', sa.String(length=48), nullable=True))
        batch_op.add_column(sa.Column('profile', sa.String(length=48), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('profile')
        batch_op.drop_column('platform')
