"""Added user table

Revision ID: cbfb208bfd59
Revises: 12d344a9fafd
Create Date: 2023-08-09 19:44:18.140807

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cbfb208bfd59'
down_revision: Union[str, None] = '12d344a9fafd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
