from sqlalchemy.future import select
from sqlalchemy.orm import Session
from src.database.modelos import User

class UserRepository():

    def __init__(self, session:Session):
      self.session = session

    async def get_all_user(self):
        async with self.session() as session:
            result = await session.execute(select(User))
            users = result.scalars().all()
            return users