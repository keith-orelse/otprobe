"""device accounts on the bundled MQTT broker (Mode A, phase L6)

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-10 10:00:00
"""
from alembic import op
import sqlalchemy as sa
import app.models.base


revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('mqtt_accounts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('topic_prefix', sa.String(length=200), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=True),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=64), nullable=False),
    sa.Column('created_at', app.models.base.UtcDateTime(), nullable=False),
    sa.Column('password_changed_at', app.models.base.UtcDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('topic_prefix'),
    sa.UniqueConstraint('username')
    )
    with op.batch_alter_table('mqtt_accounts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mqtt_accounts_asset_id'), ['asset_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('mqtt_accounts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mqtt_accounts_asset_id'))
    op.drop_table('mqtt_accounts')
