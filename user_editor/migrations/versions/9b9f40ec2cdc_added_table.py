"""Added table

Revision ID: 9b9f40ec2cdc
Revises: 
Create Date: 2023-09-12 19:57:44.980997

"""
from typing import Sequence, Union
import bcrypt

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9b9f40ec2cdc'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
                    sa.Column('id', sa.Integer(), autoincrement=True,
                              nullable=False),
                    sa.Column('username', sa.String(), nullable=False),
                    sa.Column('email', sa.String(), nullable=False),
                    sa.Column('password', sa.String(), nullable=False),
                    sa.Column('is_admin', sa.Boolean(), nullable=True),
                    sa.Column('is_editor', sa.Boolean(), nullable=True),
                    sa.Column('can_create_users', sa.Boolean(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('email'),
                    sa.UniqueConstraint('username')
                    )
    # ### end Alembic commands ###
    conn = op.get_bind()

    # Создаем хешированный пароль
    hashed_password = bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt())

    # Добавляем пользователя admin с полными правами
    conn.execute(
        sa.text(
            "INSERT INTO users (username, email, password, is_admin, is_editor, can_create_users) VALUES ('admin', 'admin@admin.com', :password, true, true, true)"
        ).bindparams(password=hashed_password)
    )


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users')
    # ### end Alembic commands ###
