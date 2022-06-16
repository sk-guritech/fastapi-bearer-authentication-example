from fastapi import FastAPI
from src.router.authenticate_api import SimpleAuthenticateAPI
from src.model.user import User
from src import SessionClass, redis_session, SECRET_KEY


app = FastAPI()

SimpleAuthenticateAPI.set_token_parameters(SECRET_KEY)
SimpleAuthenticateAPI.set_database_sessionmaker(SessionClass)
SimpleAuthenticateAPI.set_redis_session(redis_session)
SimpleAuthenticateAPI.set_user_model(User)
app.include_router(SimpleAuthenticateAPI.get_router())
