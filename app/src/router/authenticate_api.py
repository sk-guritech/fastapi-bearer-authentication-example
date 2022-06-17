from __future__ import annotations

import uuid
from datetime import datetime
from datetime import timedelta
from typing import Any

from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter
from jose import jwt
from passlib.hash import bcrypt
from redis import Redis
from sqlalchemy import String
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import Column
from src import redis_session


_api_router = InferringRouter()


class DatabaseSessionMakerNotSet(Exception):
    """Occured when session_maker is not set"""


class RedisSessionNotSet(Exception):
    """Occured when redis_session is not set."""


class RequiredColumnsNotDefined(Exception):
    """Occured when required columns are not defined."""


class AuthenticatedUser:
    """Basic user model for using SimpleAuthenticateAPI.

    Attributes:
        ulid (Column): The unique identifier of the user.
        bcrypt_hash (Column): The password hash of the user hashed by bcrypt.
        name (Column): The name of the user
    """

    ulid = Column(String(26), primary_key=True)
    bcrypt_hash = Column(String(60), nullable=False)
    name = Column(String(255), nullable=False)


@cbv(_api_router)
class SimpleAuthenticateAPI:
    '''Provides APIs for authentication.

    Attributes:
        SECRET_KEY (str): The secret key used signing for JWT.
        JWT_SIGNING_ALGORITHM (str): The algorithm used to signing JWT. Defaults to "HS256".
        ACCESS_TOKEN_EXPIRE_MINUTES (int): The period in minutes during which the access token
        can be used. Defaults to 60.
        REFRESH_TOKEN_EXPIRE_MINUTES (int): The period in minutes during which the refresh token
        can be used. Defaults to 1440.
        _database_sessionmaker (Type[sessionmaker]): SQLAlchemy database sessionmaker.
        _redis_session (Type[Redis]): Redis session.

    Raises:
        HTTPException: Occurred when authentication fails.

    Examples:
        Add APIs for authentication to FastAPI

        >>> from fastapi import FastAPI
        >>> from sqlalchemy.orm import sessionmaker
        >>> from sqlalchemy import create_engine
        >>> from authenticate_api import SimpleAuthenticateAPI, AuthenticatedUser
        >>> SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
        >>> engine = create_engine("mysql://user:password@db/database")
        >>> SessionClass = sessionmaker(engine)
        >>> app = FastAPI()
        >>> SimpleAuthenticateAPI.set_token_parameters(SECRET_KEY)
        >>> SimpleAuthenticateAPI.set_database_sessionmaker(SessionClass)
        >>> SimpleAuthenticateAPI.set_redis_session(Redis("redis", 6379, 0))
        >>> SimpleAuthenticateAPI.set_user_model(AuthenticatedUser)
        >>> app.include_router(SimpleAuthenticateAPI.get_router())
    '''
    SECRET_KEY: str = ''
    JWT_SIGNING_ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440

    _database_sessionmaker: type[sessionmaker] = sessionmaker
    _redis_session: type[Redis] = Redis
    _user_model: type[AuthenticatedUser] = AuthenticatedUser

    @staticmethod
    def get_router() -> InferringRouter:
        '''Provides the API router

        Returns:
            InferringRouter: FastAPI Router
        '''
        return _api_router

    @classmethod
    def set_database_sessionmaker(cls, database_sessionmaker) -> None:
        cls._database_sessionmaker = database_sessionmaker

    @classmethod
    def set_redis_session(cls, redis_session) -> None:
        cls._redis_session = redis_session

    @classmethod
    def set_user_model(cls, user_model) -> None:
        '''Set user model for using authentication APIs.

        Args:
            user_model (AuthenticatedUser): The user model that own neccessary columns.

        Raises:
            RequiredColumnsNotDefined: Occured when the user model don't own neccessary columns.
        '''

        if set(dir(AuthenticatedUser)) <= set(dir(user_model)):
            cls._user_model = user_model
        else:
            raise RequiredColumnsNotDefined

    @classmethod
    def set_token_parameters(
        cls, secret_key: str, jwt_signing_algorithm: str = 'HS256',
        access_token_expire_minutes: int = 60, refresh_token_expire_minutes: int = 1440,
    ) -> None:
        '''Sets signing parameters for JWT and the period during which the token can be used.

        Args:
            secret_key (str): The secret key used signing for JWT.
            jwt_signing_algorithm (str, optional): The algorithm used to signing JWT. Defaults to
            "HS256".
            access_token_expire_minutes (int, optional): The period in minutes during which the
            access token can be used. Defaults to 60.
            refresh_token_expire_minutes (int, optional): The period in minutes during which the
            refresh token can be used. Defaults to 1440.
        '''
        cls.SECRET_KEY = secret_key
        cls.JWT_SIGNING_ALGORITHM = jwt_signing_algorithm
        cls.ACCESS_TOKEN_EXPIRE_MINUTES = access_token_expire_minutes
        cls.REFRESH_TOKEN_EXPIRE_MINUTES = refresh_token_expire_minutes

    @classmethod
    def __generate_access_token(cls, ulid: str) -> tuple[Any, str]:
        claims = {
            'sub': ulid,
            'exp': datetime.utcnow() + timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES),
            'jti': ulid + ':' + uuid.uuid4().hex,
            'grant': 'access',
        }

        encoded_jwt = jwt.encode(
            claims, cls.SECRET_KEY, algorithm=cls.JWT_SIGNING_ALGORITHM,
        )

        return encoded_jwt, str(claims['jti'])

    @classmethod
    def __generate_refresh_token(cls, ulid: str) -> tuple[Any, str]:
        claims = {
            'sub': ulid,
            'exp': datetime.utcnow() + timedelta(minutes=cls.REFRESH_TOKEN_EXPIRE_MINUTES),
            'jti': ulid + ':' + uuid.uuid4().hex,
            'grant': 'refresh',
        }

        encoded_jwt = jwt.encode(
            claims, cls.SECRET_KEY, algorithm=cls.JWT_SIGNING_ALGORITHM,
        )

        return encoded_jwt, str(claims['jti'])

    @classmethod
    def __register_jtis_of_authentication_token_to_redis(
        cls, ulid: str, access_token_jti: str, refresh_token_jti: str,
    ) -> None:
        if cls._redis_session is None:
            raise RedisSessionNotSet

        cls._redis_session.set(str(ulid + ':access_token'), access_token_jti)  # type: ignore
        cls._redis_session.set(str(ulid + ':refresh_token'), refresh_token_jti)  # type: ignore

    @classmethod
    def __generate_authentication_tokens(cls, ulid: str) -> dict:
        """Generates authentication tokens and registers jtis of authentication tokens to redis."""
        access_token, access_token_jti = cls.__generate_access_token(str(ulid))
        refresh_token, refresh_token_jti = cls.__generate_refresh_token(
            str(ulid),
        )
        cls.__register_jtis_of_authentication_token_to_redis(
            str(ulid), access_token_jti, refresh_token_jti,
        )

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
        }

    @staticmethod
    def __http_exception_callback_when_username_or_password_is_incorrect() -> HTTPException:
        """Callback when username or password is incorrect."""
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authorization': 'Bearer'},
        )

    @staticmethod
    def __http_exception_callback_when_authentication_token_is_invalid() -> HTTPException:
        """Callback when authentication token is invalid."""
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid authentication token',
            headers={'WWW-Authorization': 'Bearer'},
        )

    @classmethod
    def __fetch_user_record(cls, username: str, password: str) -> type[AuthenticatedUser]:
        """Fetches the user record for the given username and password.

        Raises:
            DatabaseSessionMakerNotSet: Occurred when database_sessionmaker is not set
            HTTPException: If the password is incorrect.
        """
        if cls._database_sessionmaker is None:
            raise DatabaseSessionMakerNotSet

        db_session = cls._database_sessionmaker()
        try:
            user = db_session.query(cls._user_model).filter(
                cls._user_model.name == username,
            ).one()
        except NoResultFound:
            raise cls.__http_exception_callback_when_username_or_password_is_incorrect()
        finally:
            db_session.close()

        if bcrypt.verify(password, user.bcrypt_hash) is False:
            raise cls.__http_exception_callback_when_username_or_password_is_incorrect()

        return user

    @_api_router.post('/authenticate')
    async def __fetch_authenticate_tokens(
        self, form_data: OAuth2PasswordRequestForm = Depends(),
    ) -> dict:
        """Generates authentication tokens for the given username and password.

        Returns:
            dict: Authentication tokens.

        Raises:
            HTTPException: If username or password is incorrect.
        """

        cls = self.__class__

        user = cls.__fetch_user_record(form_data.username, form_data.password)

        return cls.__generate_authentication_tokens(str(user.ulid))

    @_api_router.post('/refresh')
    async def __refresh_authenticate_tokens(
        self, refresh_token: str = Depends(OAuth2PasswordBearer(tokenUrl='authenticate')),
    ) -> dict:
        """Refresh authentication tokens.

        Returns:
            dict: Authentication tokens.

        Raises:
            HTTPException: The authentication token is invalid.
            RedisSessionNotSet: Occured when redis session is not set.
        """

        cls = self.__class__

        claims = jwt.decode(
            refresh_token, cls.SECRET_KEY,
            algorithms=cls.JWT_SIGNING_ALGORITHM,
        )
        if claims['grant'] != 'refresh':
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()

        ulid = claims['sub']

        if cls._redis_session is None:
            raise RedisSessionNotSet

        if redis_session.get(ulid + ':refresh_token') is None:
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()

        return cls.__generate_authentication_tokens(ulid)

    @_api_router.post('/logout')
    async def __delete_authenticate_token_jtis_from_redis(
        self, access_token: str = Depends(OAuth2PasswordBearer(tokenUrl='authenticate')),
    ) -> dict:
        '''Deletes the authentication token's jtis from the redis database.

        Args:
            access_token (str, optional): Bearer access token to be used for utilizing restricted
            resources.

        Returns:
            dict: API response.

        Raises:
            HTTPException: The authentication token is invalid.
            RedisSessionNotSet: Occured when redis session is not set.
        '''
        cls = self.__class__

        claims = jwt.decode(
            access_token, cls.SECRET_KEY,
            algorithms=cls.JWT_SIGNING_ALGORITHM,
        )

        if claims['grant'] != 'access':
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()

        ulid = claims['sub']

        if cls._redis_session is None:
            raise RedisSessionNotSet

        if redis_session.get(ulid + ':refresh_token') is None:
            raise cls.__http_exception_callback_when_authentication_token_is_invalid()

        cls._redis_session.delete(ulid + ':access_token')
        cls._redis_session.delete(ulid + ':refresh_token')

        return {}
