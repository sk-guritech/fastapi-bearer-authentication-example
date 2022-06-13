from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

from sqlalchemy.schema import Column
from sqlalchemy.types import VARCHAR

class User(Base):
    __tablename__ = 'users'
    ulid = Column(VARCHAR(26), primary_key=True)
    password_hash = Column(VARCHAR(60), nullable=False)
    name = Column(VARCHAR(255), nullable=False)
    email_address = Column(VARCHAR(255), nullable=False)