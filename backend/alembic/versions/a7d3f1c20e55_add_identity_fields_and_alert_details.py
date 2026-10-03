"""add username/host/outcome to logs and severity/details to anomalies

Revision ID: a7d3f1c20e55
Revises: 2b9babfda28b
Create Date: 2026-10-02 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7d3f1c20e55'
down_revision: Union[str, Sequence[str], None] = '2b9babfda28b'   # the current newest migration
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- logs: who / where / did it work ---------------------------------
    op.add_column('logs', sa.Column('username', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('host', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('outcome', sa.String(), nullable=True))
    op.create_index(op.f('ix_logs_username'), 'logs', ['username'], unique=False)
    op.create_index(op.f('ix_logs_host'), 'logs', ['host'], unique=False)
    op.create_index(op.f('ix_logs_outcome'), 'logs', ['outcome'], unique=False)
    op.create_index(op.f('ix_logs_timestamp'), 'logs', ['timestamp'], unique=False)

    # --- anomalies: severity + evidence ----------------------------------
    # server_default makes every EXISTING alert read as "medium" instead of NULL.
    op.add_column('anomalies', sa.Column('severity', sa.String(), nullable=True, server_default='medium'))
    op.add_column('anomalies', sa.Column('details', sa.JSON(), nullable=True))
    op.create_index(op.f('ix_anomalies_severity'), 'anomalies', ['severity'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_anomalies_severity'), table_name='anomalies')
    op.drop_column('anomalies', 'details')
    op.drop_column('anomalies', 'severity')

    op.drop_index(op.f('ix_logs_timestamp'), table_name='logs')
    op.drop_index(op.f('ix_logs_outcome'), table_name='logs')
    op.drop_index(op.f('ix_logs_host'), table_name='logs')
    op.drop_index(op.f('ix_logs_username'), table_name='logs')
    op.drop_column('logs', 'outcome')
    op.drop_column('logs', 'host')
    op.drop_column('logs', 'username')
