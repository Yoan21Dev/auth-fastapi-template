from src.modules.user.scheme.UserScheme import User,UserInDB
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi.exceptions import HTTPException
from typing import Union
from fastapi import Depends
from datetime import datetime,timedelta
from config.config import Settings
from jose import jwt,JWTError
from src.modules.user.service.UserService import UserService


pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

setting = Settings()

SECRET_KEY = setting.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = setting.ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer("/auth-login")


userService = UserService()

# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
#         "disabled": False,
#     }
# }

async def get_users_db():
    users = await userService.get_all_user()
    return {user.username: {
                "username": user.username,
                "full_name": user.full_name,
                "email": user.email,
                "hashed_password": user.hashed_password,
                "disabled": user.disabled
            } for user in users}


def get_user(db,username):
    if username in db:
        user_data= db[username]
        return UserInDB(**user_data)
    return []

def verify_password(plabe_password, hashed_password):
    return pwd_context.verify(plabe_password,hashed_password)

def authenticate_user(db, username,password):
    user = get_user(db,username)
    if not user:
        raise HTTPException(status_code=401, detail="could not validate crendentials", headers={"www-Authenticate0":"Bearer"})
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="could not validate crendentials", headers={"www-Authenticate0":"Bearer"})
    return user

def create_token(data: dict, time_expire:Union[datetime,None]= None):
    data_copy = data.copy()
    if time_expire is None: 
        expires = datetime.utcnow() + timedelta(minutes=15)
    else:
        expires = datetime.utcnow() +time_expire
    data_copy.update({"exp": expires})
    token_jwt = jwt.encode(data_copy,key=SECRET_KEY,algorithm=ALGORITHM)
    return token_jwt

async def get_user_current(token: str = Depends(oauth2_scheme)):
    try:
        token_decode = jwt.decode(token, key=SECRET_KEY, algorithms=[ALGORITHM]) 
        username = token_decode.get("sub")
        if username == None:
            raise HTTPException(status_code=401, detail="could not validate crendentials", headers={"www-Authenticate0":"Bearer"})
    
    except JWTError as e :
        raise HTTPException(status_code=401, detail="could not validate crendentials", headers={"www-Authenticate0":"Bearer"})
    users_db = await get_users_db()

    user = get_user(users_db, username)
    
    if not user:
        raise HTTPException(status_code=401, detail="could not validate crendentials", headers={"www-Authenticate0":"Bearer"})
    return user

def get_user_disabled_current(user: User = Depends(get_user_current)):
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive User", headers={"www-Authenticate0":"Bearer"})
    return user
    