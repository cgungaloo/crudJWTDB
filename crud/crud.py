from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from models.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_user_from_db(username: str, db: Session): 
    return db.query(User).filter(User.username == username).first()

def get_all_usernames(db: Session):
    users = db.query(User).all()
    users_list = []
    for user in users:
        users_list.append(user.username)
    return users_list

    