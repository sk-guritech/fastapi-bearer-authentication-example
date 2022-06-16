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

_api_router = InferringRouter()
@cbv(_api_router)
class SimpleAuthenticateAPI(object):
    '''Provides APIs for authentication.

    Attributes:
        SECRET_KEY (str): The secret key used signing for JWT.
        JWT_SIGNING_ALGORITHM (str): The algorithm used to signing JWT. Defaults to "HS256".
        ACCESS_TOKEN_EXPIRE_MINUTES (int): The period in minutes during which the access token can be used. Defaults to 60.
        REFRESH_TOKEN_EXPIRE_MINUTES (int): The period in minutes during which the refresh token can be used. Defaults to 1440.

    Raises:
        HTTPException: Occurred when authentication fails.

    Examples:
        Add APIs for authentication to FastAPI
        
        >>> from fastapi import FastAPI
        >>> from authenticate_api import SimpleAuthenticateAPI
        >>> SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
        >>> app = FastAPI()
        >>> SimpleAuthenticateAPI.set_token_parameters(SECRET_KEY)
        >>> app.include_router(SimpleAuthenticateAPI.get_router())
    '''    
    SECRET_KEY: str = ''
    JWT_SIGNING_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    
    @staticmethod
    def get_router() -> InferringRouter:
        '''Provides the API router

        Returns:
            InferringRouter: FastAPI Router
        '''            
        return _api_router
    
    @classmethod
    def set_token_parameters(cls, secret_key: str, jwt_signing_algorithm: str = "HS256", access_token_expire_minutes: int = 60, refresh_token_expire_minutes: int = 1440) -> None:
        '''Sets JWT signing parameters and the period during which the token can be used.

        Args:
            secret_key (str): The secret key used signing for JWT.
            jwt_signing_algorithm (str, optional): The algorithm used to signing JWT. Defaults to "HS256".
            access_token_expire_minutes (int, optional): The period in minutes during which the access token can be used. Defaults to 60.
            refresh_token_expire_minutes (int, optional): The period in minutes during which the refresh token can be used. Defaults to 1440.
        '''
        cls.SECRET_KEY = secret_key
        cls.JWT_SIGNING_ALGORITHM = jwt_signing_algorithm
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
        
        encoded_jwt = jwt.encode(claims, cls.SECRET_KEY, algorithm=cls.JWT_SIGNING_ALGORITHM)
        
        return encoded_jwt, claims["jti"]

    @classmethod
    def __generate_refresh_token(cls, ulid: str) -> tuple[str, str]:
        claims = {
            "sub": ulid,
            "exp": datetime.utcnow() + timedelta(minutes=cls.REFRESH_TOKEN_EXPIRE_MINUTES),
            "jti": ulid + ":" + uuid.uuid4().hex,
            "grant": "refresh"
        }
        
        encoded_jwt = jwt.encode(claims, cls.SECRET_KEY, algorithm=cls.JWT_SIGNING_ALGORITHM)
        
        return encoded_jwt, claims["jti"]

    @staticmethod
    def __register_jtis_of_authentication_token_to_redis(ulid: str, access_token_jti: str, refresh_token_jti: str) -> None:
        redis_session.set(ulid + ":access_token", access_token_jti)
        redis_session.set(ulid + ":refresh_token",refresh_token_jti)

    @classmethod
    def __generate_authentication_tokens(cls, ulid: str) -> dict:
        """Generates authentication tokens and registers jtis of authentication tokens to redis."""
        access_token, access_token_jti = cls.__generate_access_token(str(ulid))
        refresh_token, refresh_token_jti = cls.__generate_refresh_token(str(ulid))
        cls.__register_jtis_of_authentication_token_to_redis(str(ulid), access_token_jti, refresh_token_jti)
        
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    @staticmethod
    def __http_exception_callback_when_username_or_password_is_incorrect() -> HTTPException:
        """Callback when username or password is incorrect."""
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authorization":"Bearer"}        
        )
    
    @staticmethod
    def __http_exception_callback_when_authentication_token_is_invalid() -> HTTPException:
        """Callback when authentication token is invalid."""
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authorization":"Bearer"}        
        )
        
    @classmethod
    def __fetch_user_record(cls, username: str, password: str) -> User:
        """Fetches the user record for the given username and password.
        
        Raises:
            HTTPException: If the password is incorrect.
        """
        try:
            user = db_session.query(User).filter(User.name == username).one()
        except NoResultFound:
            raise cls.__http_exception_callback_when_username_or_password_is_incorrect()            

        if bcrypt.verify(password, user.password_hash) == False:        
            raise cls.__http_exception_callback_when_username_or_password_is_incorrect()
               
        return user

    @_api_router.post("/authenticate")
    async def __fetch_authenticate_tokens(self, form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
        """Generates authentication tokens for the given username and password.
        
        Returns:
            dict: Authentication tokens.

        Raises: 
            HTTPException: If username or password is incorrect.
        """
        
        cls = self.__class__
        
        user = cls.__fetch_user_record(form_data.username, form_data.password)
            
        return cls.__generate_authentication_tokens(str(user.ulid))

    @_api_router.post("/refresh")
    async def __refresh_authenticate_tokens(self, refresh_token: str = Depends(OAuth2PasswordBearer(tokenUrl="authenticate"))) -> dict:
        """Refresh authentication tokens.
        
        Returns:
            dict: Authentication tokens.

        Raises:
            HTTPException: The authentication token is invalid
        """

        cls = self.__class__

        claims = jwt.decode(refresh_token, cls.SECRET_KEY, algorithms=cls.JWT_SIGNING_ALGORITHM)        
        if claims["grant"] != "refresh":
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()
        
        ulid = claims["sub"]
        if redis_session.get(ulid + ":refresh_token") is None:
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()
        
        return cls.__generate_authentication_tokens(ulid)

    @_api_router.post("/logout")
    async def __delete_authenticate_token_jtis_from_redis(self, access_token: str = Depends(OAuth2PasswordBearer(tokenUrl="authenticate"))) -> dict:
        '''Deletes the authentication token's jtis from the redis database.

        Args:
            access_token (str, optional): Bearer access token to be used for utilizing restricted resources.

        Returns:
            dict: API response.
            
        Raises: 
            HTTPException: The authentication token is invalid
        '''        
        cls = self.__class__
        
        claims = jwt.decode(access_token, cls.SECRET_KEY, algorithms=cls.JWT_SIGNING_ALGORITHM)
        
        if claims["grant"] != "access":
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()
            
        ulid = claims["sub"]
        redis_session.delete(ulid + ":access_token")
        redis_session.delete(ulid + ":refresh_token")
        
        return {}