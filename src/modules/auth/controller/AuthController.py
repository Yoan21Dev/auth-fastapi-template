from fastapi import APIRouter
from fastapi import FastAPI,Depends,HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from src.modules.auth.service.AuthService import authenticate_user,get_users_db,create_token
from datetime import timedelta

authRouter = APIRouter()

@authRouter.post("/auth-login")
async def login(form_data:OAuth2PasswordRequestForm = Depends()):
    
    users_db = await get_users_db()
    user = authenticate_user(users_db, form_data.username,form_data.password)
    
    access_token_expire = timedelta(minutes=30)
    
    access_token_jwt = create_token({"sub":user.username},access_token_expire)
    
    return {
        "access_token": access_token_jwt,
        "token_type": "bearer"
    }



