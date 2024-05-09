from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Annotated

from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status
from fastapi.concurrency import asynccontextmanager
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field
from sqlmodel import Relationship
from sqlmodel import Session
from sqlmodel import SQLModel
from sqlmodel import create_engine
from sqlmodel import select
from PIL import Image

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class Message(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    parent_id: int | None
    content: str = Field(nullable=False)
    author_id: int = Field(nullable=False, foreign_key="user.id")
    author: "User" = Relationship()


class UserGroupLink(SQLModel, table=True):
    user_id: int | None = Field(default=None, foreign_key="user.id", primary_key=True)
    group_id: int | None = Field(default=None, foreign_key="group.id", primary_key=True)


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, nullable=False)
    password: str = Field(nullable=False)
    avatar: str | None = Field(default=None)
    disabled: bool | None = None
    groups: list["Group"] = Relationship(
        back_populates="members",
        link_model=UserGroupLink,
    )


class LoginResponse(Token):
    username: str
    avatar: str | None = None
    disabled: bool | None = None


class GroupBase(SQLModel):
    name: str = Field(index=True, nullable=False)
    owner_id: int | None = Field(foreign_key="user.id")
    private: bool = Field(default=False)
    last_message_id: int | None = Field(default=None, foreign_key="message.id")


class Group(GroupBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    members: list["User"] = Relationship(
        back_populates="groups",
        link_model=UserGroupLink,
    )

    last_message: Message | None = Relationship(
        sa_relationship_kwargs={"lazy": "joined"},
    )


class GroupWithMessage(GroupBase):
    last_message: Message | None = None


DB_URL = "postgresql://postgres:postgres@localhost:5432/postgres"

engine = create_engine(DB_URL, echo=True)


def create_db_and_tables():
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the ML model
    create_db_and_tables()
    user = create_user(User(username="test", password="test"))
    user2 = create_user(User(username="test2", password="test"))
    my_id = user2.id
    group = await create_group("Test Group", [user, user2], True, user)
    send_message_to_group(group.id, "Test message", my_id)
    yield


app = FastAPI(lifespan=lifespan)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    with Session(engine) as session:
        return session.exec(select(User).where(User.username == username)).first()


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_avatar(initials, size=128, bgcolor=None, textcolor=None):
    img_size = (size, size)
    color1 = 
    
    img = Image.new("RGB", img_size, color=bgcolor)
    draw = ImageDraw.Draw(img)

    # Load the default font with a custom size
    font = ImageFont.load_default()

    # Calculate text width and height
    bounding_box = font.getbbox(initials)
    text_width = bounding_box[2] - bounding_box[0]
    text_height = bounding_box[3] - bounding_box[1]

    # Calculate position for centered text
    position = ((img_size[0] - text_width) / 2, (img_size[1] - text_height) / 2)

    draw.text(position, initials, fill=textcolor, font=font)
    return img


@app.post("/users/")
def create_user(user: User):
    user.password = get_password_hash(user.password)
    with Session(engine) as session:
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


@app.get("/users/")
def read_users():
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return users


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@app.post("/token")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> LoginResponse:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username,
        avatar=user.avatar,
        disabled=user.disabled,
    )


@app.post("/groups/")
async def create_group(
    name: str,
    members: list[User],
    private: bool = False,
    current_user: User = Depends(get_current_user),
):
    if private and len(members) != 2:
        raise HTTPException(
            status_code=400,
            detail="Private group must have exactly two members",
        )

    group = Group(name=name, owner_id=current_user.id, private=private, members=members)

    with Session(engine) as session:
        session.add(group)
        session.commit()
        session.refresh(group)

        return group


@app.get("/groups/")
async def list_groups(
    current_user: User = Depends(get_current_user),
) -> list[GroupWithMessage]:
    with Session(engine) as session:
        statement = select(Group).join(
            UserGroupLink,
            UserGroupLink.user_id == current_user.id,
        )

        return session.exec(statement).all()


@app.post("/groups/{group_id}/add-user/{user_id}")
async def add_user_to_group(group_id: int, user_id: int):
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        group.members.append(user)
        session.commit()
        return {
            "message": f"User '{user.username}' added to group '{group.name}' successfully",
        }


@app.get("/groups/{group_id}/members")
async def get_group_members(group_id: int):
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        return group.members


def send_message_to_group(group_id: int, message_content: str, sender_id: int):
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Create the message
        message = Message(content=message_content, author_id=sender_id)
        session.add(message)
        session.commit()
        session.refresh(message)

        # Update the group's last message
        group.last_message = message
        session.commit()

        return message


@app.post("/groups/{group_id}/send-message")
async def send_message(
    group_id: int,
    message_content: str,
    current_user: User = Depends(get_current_user),
):
    return send_message_to_group(group_id, message_content, current_user.id)


@app.get("/groups/{group_id}/messages")
async def get_group_messages(group_id: int, limit: int = 10):
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Fetch the messages for the group with the specified limit
        messages = session.exec(
            select(Message)
            .where(Message.parent_id == group_id)
            .order_by(Message.id.desc())
            .limit(limit),
        ).all()

        return messages
