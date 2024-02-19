from datetime import timedelta
from typing import Annotated, List
import uuid
from fastapi import FastAPI, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from crud.crud import check_item_exists_for_user, create_user_item, get_all_usernames, get_items_for_user, get_user_from_db
from db.db import SessionLocal, engine
from schemas import schemas
from models import models
from utils.utils import create_access_token, get_current_active_user, hash_pass, verify_password
from models.models import Base, Item, User

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():

   db = SessionLocal()
   print(f'db: {db}')
   try:
      yield db
   finally:
      db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token")
async def login_for_access_token(
   form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> schemas.Token:
   db = SessionLocal()
   print(db)
   print(type(db))
   user = get_user_from_db(form_data.username, db)
   if not user:
      raise HTTPException(status_code=400, detail= "Incorrect username or password")
   
   verfied_pwd = verify_password(form_data.password, user.password)

   if not verfied_pwd:
      raise HTTPException(status_code=400, detail = "Incorrect Password")
   
   ACCESS_TOKEN_EXPIRE_MINUTES = 30
   access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
   
   access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
   
   return schemas.Token(access_token=access_token, token_type="bearer")

@app.post("/")
def create_users(user: schemas.UserCreate, db:Session = Depends(get_db)):
   hashed_pass = hash_pass(user.password)

   user.password = hashed_pass
   id = str(uuid.uuid4())
   user_dict = user.model_dump()
   user_dict['id'] = id
   new_user = models.User(**user_dict)
   db.add(new_user)
   db.commit()
   db.refresh(new_user)

   return new_user

@app.get("/users", response_model= List[str])
def get_current_users(current_user: Annotated[User, Depends(get_current_active_user)]):
   print(f'CURRENT USER MAIN : {current_user}')
   db = SessionLocal()
   return get_all_usernames(db)

@app.post("/users/items/")
async def create_item(current_user: Annotated[User, Depends(get_current_active_user)] ,item: schemas.ItemCreate, db:Session = Depends(get_db)):
   print(f'Creating Item ...')
   user_id = current_user.id
   item_dict = item.model_dump()
   id = str(uuid.uuid4())
   item_dict['id'] = id
   item_dict['owner_id'] = user_id
   db_item = Item(**item_dict)
   return create_user_item(db=db, item=db_item, user_id=user_id)

@app.get("/users/items", response_model=list[schemas.Item])
async def get_user_items(current_user: Annotated[User, Depends(get_current_active_user)], 
                         db: Session = Depends(get_db)):
   print(f'Getting Items for {user_id} ...')
   user_id = current_user.id

   items = get_items_for_user(user_id, db)
   
   return items

@app.put("/users/items/{item_id}", response_model=schemas.Item)
async def update_item(item_id:str,current_user: Annotated[User, Depends(get_current_active_user)],item : schemas.Item, 
                      db:Session = Depends(get_db)):
   print(f'Updating for {item_id}')
   user_id = current_user.id

   exists = check_item_exists_for_user(user_id,item_id,db)

   print(f"Item exists : {exists}")
   return item



   