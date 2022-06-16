from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import Column
from src.router.authenticate_api import AuthenticatedUser
Base = declarative_base()


class User(AuthenticatedUser, Base):
    __tablename__ = 'users'
    email_address = Column(String(255), nullable=False)
