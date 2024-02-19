from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from models.models import Item, User
from schemas import schemas

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_user_from_db(username: str, db: Session): 
    return db.query(User).filter(User.username == username).first()

def get_all_usernames(db: Session):
    users = db.query(User).all()
    users_list = []
    for user in users:
        users_list.append(user.username)
    return users_list


def create_user_item(db: Session, item: Item, user_id: str):
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

def get_items_for_user(user_id: str, db: Session):
    return db.query(Item).filter(Item.owner_id == user_id).all()

def check_item_exists_for_user(user_id: str,item_id : str, db:Session):
    item = db.query(Item).filter(Item.owner_id == user_id, Item.id == item_id).first()
    if item:
        return item

    return None



    