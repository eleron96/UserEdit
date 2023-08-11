from sqlalchemy import Integer, Column, String, Boolean

from user_editor.db import BaseDBModel


class User(BaseDBModel):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    is_editor = Column(Boolean, default=False)
    can_create_users = Column(Boolean, default=False)