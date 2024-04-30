from src.modules.user.repository.UserRepository import UserRepository
from src.database.db import SessionLocal

class UserService():
    def __init__(self):
      self.userRepository = UserRepository(SessionLocal)

    async def get_all_user(self):
        return await self.userRepository.get_all_user()