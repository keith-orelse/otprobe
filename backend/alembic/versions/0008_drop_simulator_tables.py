"""drop the simulator tables (the simulator moved into the test suite, phase L6)

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-06 10:00:00
"""
from alembic import op
import sqlalchemy as sa
import app.models.base


revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

SIM_TABLES = ('sim_mqtt_clients', 'sim_meta', 'sim_faults', 'sim_devices')


def upgrade() -> None:
    for table in SIM_TABLES:
        op.drop_table(table)


def downgrade() -> None:
    op.create_table('sim_devices',
    sa.Column('device_id', sa.String(length=64), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('vendor', sa.String(length=255), nullable=False),
    sa.Column('model', sa.String(length=255), nullable=False),
    sa.Column('device_type', sa.String(length=64), nullable=False),
    sa.Column('level', sa.String(length=8), nullable=False),
    sa.Column('powered', sa.Boolean(), nullable=False),
    sa.Column('state', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('device_id'),
    sa.UniqueConstraint('ip'),
    sa.UniqueConstraint('mac')
    )
    op.create_table('sim_faults',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('device_id', sa.String(length=64), nullable=False),
    sa.Column('fault', sa.String(length=64), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('set_by', sa.String(length=64), nullable=False),
    sa.Column('set_at', app.models.base.UtcDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'fault')
    )
    op.create_table('sim_meta',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('sim_mqtt_clients',
    sa.Column('client_id', sa.String(length=64), nullable=False),
    sa.Column('device_id', sa.String(length=64), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=False),
    sa.Column('connected', sa.Boolean(), nullable=False),
    sa.Column('topics', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('client_id')
    )
