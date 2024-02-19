from pydantic import BaseModel

class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    password: str


class ItemBase(BaseModel):
    title: str
    description: str | None = None


class ItemCreate(ItemBase):
    pass

class Login(BaseModel):
    username : str
    password: str

class Item(ItemBase):
    id: str
    owner_id: str

    class Config:
        orm_mode = True

class User(UserBase):
    id: str
    items: list[Item] = []

    class Config:
        orm_mode = True

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
