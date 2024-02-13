from datetime import timedelta
from typing import Annotated, List
import uuid
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from crud.crud import get_all_usernames, get_user_from_db
from db.db import SessionLocal, engine
from schemas import schemas
from models import models
from utils.utils import create_access_token, get_current_active_user, hash_pass, verify_password
from models.models import Base, User

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