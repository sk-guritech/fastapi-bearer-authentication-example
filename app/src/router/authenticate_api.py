from datetime import datetime, timedelta
from typing import Dict
import uuid
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import redis
from sqlalchemy.exc import NoResultFound
from passlib.hash import bcrypt
import ulid
from src import db_session, redis_session
from src.model.user import User
from jose import JWTError, jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
JWT_ENCODE_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTE = 60
REFRESH_TOKEN_EXPIRE_MINUTE = 1440

api_router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="authenticate")

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
    
def generate_access_token(ulid: str) -> tuple[str, str]:
    claims = {
        "sub": ulid,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTE),
        "jti": ulid + ":" + uuid.uuid4().hex,
        "grant": "access"
    }
    
    encoded_jwt = jwt.encode(claims, SECRET_KEY, algorithm=JWT_ENCODE_ALGORITHM)
    
    return encoded_jwt, claims["jti"]

def generate_refresh_token(ulid: str) -> tuple[str, str]:
    claims = {
        "sub": ulid,
        "exp": datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTE),
        "jti": ulid + ":" + uuid.uuid4().hex,
        "grant": "refresh"
    }
    
    encoded_jwt = jwt.encode(claims, SECRET_KEY, algorithm=JWT_ENCODE_ALGORITHM)
    
    return encoded_jwt, claims["jti"]

def register_authenticate_token_jtis_to_redis(ulid: str, access_token_jti: str, refresh_token_jti: str) -> None:
    redis_session.set(ulid + ":access_token", access_token_jti)
    redis_session.set(ulid + ":refresh_token",refresh_token_jti)
    

@api_router.post("/authenticate")
async def fetch_authenticate_tokens(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fetch_user_record(form_data.username, form_data.password)
    access_token, access_token_jti = generate_access_token(str(user.ulid))
    refresh_token, refresh_token_jti = generate_refresh_token(str(user.ulid))
    register_authenticate_token_jtis_to_redis(str(user.ulid), access_token_jti, refresh_token_jti)
        
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@api_router.post("/refresh")
async def refresh_authenticate_tokens(refresh_token: str = Depends(oauth2_scheme)):
    claims = jwt.decode(refresh_token, SECRET_KEY, algorithms=JWT_ENCODE_ALGORITHM)
    
    if claims["grant"] != "refresh":
        unauthorized_callback()
    
    ulid = claims["sub"]
    
    if redis_session.get(ulid + ":refresh_token") is None:
        unauthorized_callback()
    
    access_token, access_token_jti = generate_access_token(ulid)
    refresh_token, refresh_token_jti = generate_refresh_token(ulid)
    register_authenticate_token_jtis_to_redis(ulid, access_token_jti, refresh_token_jti)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@api_router.post("/logout")
async def delete_authenticate_token_jtis_from_redis(access_token: str = Depends(oauth2_scheme)):
    claims = jwt.decode(access_token, SECRET_KEY, algorithms=JWT_ENCODE_ALGORITHM)
    
    if claims["grant"] != "access":
        unauthorized_callback()
        
    ulid = claims["sub"]
    redis_session.delete(ulid + ":access_token")
    redis_session.delete(ulid + ":refresh_token")
    
    return {}