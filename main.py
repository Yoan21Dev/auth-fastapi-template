from fastapi import FastAPI,Depends,HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext
from datetime import datetime,timedelta
from jose import jwt,JWTError

app = FastAPI()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

oauth2_scheme = OAuth2PasswordBearer("/token")

pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

class User(BaseModel):
    username: str
    full_name: Union[str,None] = None
    email: Union[str,None] = None
    disabled: Union[bool,None] = None

class UserInDB(User):
    hashed_password: str


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

def get_user_current(token: str, ):
    try:
           token_decode = jwt.decode(token, key) 

    except JWTError as e :
        pass 

@app.get("/")
def root():
    return "hi am FastApi"

@app.get("/users/me")
def user(token: str = Depends(oauth2_scheme)):
    return token

@app.post("/token")
def login(form_data:OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db,form_data.username,form_data.password)
    access_token_expire = timedelta(minutes=30)
    access_token_jwt=create_token({"sub":user.username},access_token_expire)
    return {
        "access_token": access_token_jwt,
        "token_type": "bearer"
    }