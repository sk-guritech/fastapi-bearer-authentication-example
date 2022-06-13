from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from redis import Redis

__engine = create_engine("mysql://user:password@db/database")
__SessionClass = sessionmaker(__engine)

db_session = __SessionClass()
redis_session = Redis("redis", 6379, 0)