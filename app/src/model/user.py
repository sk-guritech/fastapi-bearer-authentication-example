from sqlalchemy import String
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

from sqlalchemy.schema import Column

class User(Base):
    __tablename__ = 'users'
    ulid = Column(String(26), primary_key=True)
    password_hash = Column(String(60), nullable=False)
    name = Column(String(255), nullable=False)
    email_address = Column(String(255), nullable=False)
    