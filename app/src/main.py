from fastapi import FastAPI
from src.router import authenticate_api

app = FastAPI()
app.include_router(authenticate_api.api_router)