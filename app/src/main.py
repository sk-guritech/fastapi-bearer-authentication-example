from __future__ import annotations

from fastapi import FastAPI
from src import redis_session
from src import SECRET_KEY
from src import SessionClass
from src.model.user import User
from src.router.authenticate_api import SimpleAuthenticateAPI


app = FastAPI()

SimpleAuthenticateAPI.set_token_parameters(SECRET_KEY)
SimpleAuthenticateAPI.set_database_sessionmaker(SessionClass)
SimpleAuthenticateAPI.set_redis_session(redis_session)
SimpleAuthenticateAPI.set_user_model(User)
app.include_router(SimpleAuthenticateAPI.get_router())
