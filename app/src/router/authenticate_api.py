from datetime import datetime, timedelta
import uuid
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.exc import NoResultFound
from passlib.hash import bcrypt
from src import db_session, redis_session
from src.model.user import User
from jose import JWTError, jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
JWT_ENCODE_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTE = 60
REFRESH_TOKEN_EXPIRE_MINUTE = 1440

api_router = APIRouter()

def unauthorized_callback():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authorization":"Bearer"}        
    )

def fetch_user_record(username: str, password: str) -> User:
    try:
        user = db_session.query(User).filter(User.name == username).one()
        
        if bcrypt.verify(password, user.password_hash):
            return user
        
        unauthorized_callback()
    except (NoResultFound, ValueError):
        unauthorized_callback()
    
def generate_access_token(ulid: str) -> str:
    claims = {
        "sub": ulid,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTE),
        "jti": ulid + ":" + uuid.uuid4().hex,
        "grant": "access"
    }
    
    encoded_jwt = jwt.encode(claims, SECRET_KEY, algorithm=JWT_ENCODE_ALGORITHM)
    redis_session.set(ulid + ":access_token",claims["jti"])
    
    return encoded_jwt

def generate_refresh_token(ulid: str) -> str:
    claims = {
        "sub": ulid,
        "exp": datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTE),
        "jti": ulid + ":" + uuid.uuid4().hex,
        "grant": "access"
    }
    
    encoded_jwt = jwt.encode(claims, SECRET_KEY, algorithm=JWT_ENCODE_ALGORITHM)
    redis_session.set(ulid + ":refresh_token",claims["jti"])
    
    return encoded_jwt

@api_router.post("/authenticate")
def fetch_authenticate_tokens(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fetch_user_record(form_data.username, form_data.password)
    access_token = generate_access_token(user.ulid)
    refresh_token = generate_refresh_token(user.ulid)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    