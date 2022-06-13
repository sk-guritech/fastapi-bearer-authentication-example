from user import User
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = FastAPI()
engine = create_engine("mysql://user:password@db/database")
SessionClass = sessionmaker(engine)
session = SessionClass()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/user")
async def get_user():
    users = session.query(User).all()
    return users
