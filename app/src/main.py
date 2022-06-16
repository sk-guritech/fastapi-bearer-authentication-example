from fastapi import FastAPI
from src.router.authenticate_api import SimpleAuthenticateAPI

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

app = FastAPI()

SimpleAuthenticateAPI.set_token_parameters(SECRET_KEY)
app.include_router(SimpleAuthenticateAPI.get_router())
