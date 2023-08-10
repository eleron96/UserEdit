"""Added user table

Revision ID: 776146360cef
Revises: cbfb208bfd59
Create Date: 2023-08-09 19:45:13.795056

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '776146360cef'
down_revision: Union[str, None] = 'cbfb208bfd59'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
