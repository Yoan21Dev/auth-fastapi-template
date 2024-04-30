from fastapi import APIRouter,Depends
from src.modules.auth.service.AuthService import get_user_disabled_current,get_user_current
from src.modules.user.scheme.UserScheme import User
from src.modules.user.repository.UserRepository import UserRepository
from src.modules.user.service.UserService import UserService


userRouter = APIRouter(dependencies=[Depends(get_user_current)])

userService = UserService()

@userRouter.get("/users/me")
def user(user: User = Depends(get_user_disabled_current)):
    return user

@userRouter.get("/users")
async def users():
    return await userService.get_all_user()

