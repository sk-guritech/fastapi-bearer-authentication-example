from datetime import datetime, timedelta
import uuid
from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.exc import NoResultFound
from passlib.hash import bcrypt
from src import db_session, redis_session
from src.model.user import User
from jose import jwt

from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter
api_router = InferringRouter()

@cbv(api_router)
class SimpleAuthenticateAPI:
    SECRET_KEY: str = ''
    JWT_ENCODE_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    
    @classmethod
    def set_token_parameters(cls, secret_key: str, jwt_encode_algorithm: str = "HS256", access_token_expire_minutes: int = 60, refresh_token_expire_minutes: int = 1440) -> None:
        cls.SECRET_KEY = secret_key
        cls.JWT_ENCODE_ALGORITHM = jwt_encode_algorithm
        cls.ACCESS_TOKEN_EXPIRE_MINUTES = access_token_expire_minutes
        cls.REFRESH_TOKEN_EXPIRE_MINUTES = refresh_token_expire_minutes
    
    @classmethod
    def __generate_access_token(cls, ulid: str) -> tuple[str, str]:
        claims = {
            "sub": ulid,
            "exp": datetime.utcnow() + timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES),
            "jti": ulid + ":" + uuid.uuid4().hex,
            "grant": "access"
        }
        
        encoded_jwt = jwt.encode(claims, cls.SECRET_KEY, algorithm=cls.JWT_ENCODE_ALGORITHM)
        
        return encoded_jwt, claims["jti"]

    @classmethod
    def __generate_refresh_token(cls, ulid: str) -> tuple[str, str]:
        claims = {
            "sub": ulid,
            "exp": datetime.utcnow() + timedelta(minutes=cls.REFRESH_TOKEN_EXPIRE_MINUTES),
            "jti": ulid + ":" + uuid.uuid4().hex,
            "grant": "refresh"
        }
        
        encoded_jwt = jwt.encode(claims, cls.SECRET_KEY, algorithm=cls.JWT_ENCODE_ALGORITHM)
        
        return encoded_jwt, claims["jti"]

    @staticmethod
    def __register_authenticate_token_jtis_to_redis(ulid: str, access_token_jti: str, refresh_token_jti: str) -> None:
        redis_session.set(ulid + ":access_token", access_token_jti)
        redis_session.set(ulid + ":refresh_token",refresh_token_jti)

    @staticmethod
    def __unauthorized_callback() -> None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authorization":"Bearer"}        
        )
    
    @classmethod
    def __fetch_user_record(cls, username: str, password: str) -> User:
        try:
            user = db_session.query(User).filter(User.name == username).one()
            
            if bcrypt.verify(password, user.password_hash):
                return user
            
            cls.__unauthorized_callback()
        except (NoResultFound, ValueError):
            cls.__unauthorized_callback()
        
    @api_router.post("/authenticate")
    async def fetch_authenticate_tokens(self, form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
        cls = self.__class__
        user = cls.__fetch_user_record(form_data.username, form_data.password)
        access_token, access_token_jti = cls.__generate_access_token(str(user.ulid))
        refresh_token, refresh_token_jti = cls.__generate_refresh_token(str(user.ulid))
        cls.__register_authenticate_token_jtis_to_redis(str(user.ulid), access_token_jti, refresh_token_jti)
            
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    @api_router.post("/refresh")
    async def refresh_authenticate_tokens(self, refresh_token: str = Depends(OAuth2PasswordBearer(tokenUrl="authenticate"))) -> dict:
        cls = self.__class__
        claims = jwt.decode(refresh_token, cls.SECRET_KEY, algorithms=cls.JWT_ENCODE_ALGORITHM)
        
        if claims["grant"] != "refresh":
            cls.__unauthorized_callback()
        
        ulid = claims["sub"]
        
        if redis_session.get(ulid + ":refresh_token") is None:
            cls.__unauthorized_callback()
        
        access_token, access_token_jti = cls.__generate_access_token(ulid)
        refresh_token, refresh_token_jti = cls.__generate_refresh_token(ulid)
        cls.__register_authenticate_token_jtis_to_redis(ulid, access_token_jti, refresh_token_jti)
        
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    @api_router.post("/logout")
    async def delete_authenticate_token_jtis_from_redis(self, access_token: str = Depends(OAuth2PasswordBearer(tokenUrl="authenticate"))) -> dict:
        cls = self.__class__
        claims = jwt.decode(access_token, cls.SECRET_KEY, algorithms=cls.JWT_ENCODE_ALGORITHM)
        
        if claims["grant"] != "access":
            cls.__unauthorized_callback()
            
        ulid = claims["sub"]
        redis_session.delete(ulid + ":access_token")
        redis_session.delete(ulid + ":refresh_token")
        
        return {}