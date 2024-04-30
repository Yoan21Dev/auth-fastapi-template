import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = os.getenv("SECRET_KEY","Secret")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = os.getenv("TOKEN_EXPIRE_MINUTES",30)
    
    HOST_DB: str = os.getenv("HOST_DB","localhost")
    PORT_DB: int = os.getenv("PORT_DB",5432)

    USER_DB: str = os.getenv("USER_DB","postgres")
    PASSWORD_DB: str = os.getenv("PASSWORD_DB","postgres")
    NAME_DB: str = os.getenv("NAME_DB","none")