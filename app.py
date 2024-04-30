from fastapi import FastAPI

from src.modules.auth.controller.AuthController import authRouter
from src.modules.user.controller.UserController import userRouter
app = FastAPI()

app.include_router(authRouter,tags=['Authentication route'])
app.include_router(userRouter,tags=['Users route'])