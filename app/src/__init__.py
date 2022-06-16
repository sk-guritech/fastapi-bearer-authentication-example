from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from redis import Redis

__engine = create_engine("mysql://user:password@db/database")
SessionClass = sessionmaker(__engine)

redis_session = Redis("redis", 6379, 0)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"