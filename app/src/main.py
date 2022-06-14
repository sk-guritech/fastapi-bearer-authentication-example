from fastapi import FastAPI
from src.router import authenticate_api

app = FastAPI()
authenticate_api.SimpleAuthenticateAPI.set_token_parameters("09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
app.include_router(authenticate_api.api_router)