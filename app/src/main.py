from __future__ import annotations

from fastapi import FastAPI
from src import redis_session
from src import SECRET_KEY
from src import SessionClass
from src.model.user import User
from src.router.authenticate_api import FastAPISimpleAuthentication


app = FastAPI()

FastAPISimpleAuthentication.set_token_parameters(SECRET_KEY)
FastAPISimpleAuthentication.set_database_sessionmaker(SessionClass)
FastAPISimpleAuthentication.set_redis_session(redis_session)
FastAPISimpleAuthentication.set_user_model(User)
app.include_router(FastAPISimpleAuthentication.get_router())
