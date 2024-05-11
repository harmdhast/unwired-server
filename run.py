import base64
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from io import BytesIO
from typing import Annotated

import distinctipy
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
from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont
from pydantic import BaseModel
from sqlalchemy.orm import joinedload
from sqlmodel import Field
from sqlmodel import Relationship
from sqlmodel import Session
from sqlmodel import SQLModel
from sqlmodel import col
from sqlmodel import create_engine
from sqlmodel import select
from sqlmodel import text

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class MessageBase(SQLModel):
    parent_id: int | None
    content: str = Field(nullable=False)
    group_id: int | None = Field(
        default=None, foreign_key="group.id", index=True)


class Message(MessageBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    author: "User" = Relationship()
    author_id: int = Field(nullable=False, foreign_key="user.id", index=True)
    at: datetime | None = Field(
        # default_factory=datetime.now,
        sa_column_kwargs={"server_default": text("CURRENT_TIMESTAMP")},
    )


class UserGroupLink(SQLModel, table=True):
    user_id: int | None = Field(
        default=None, foreign_key="user.id", primary_key=True)
    group_id: int | None = Field(
        default=None, foreign_key="group.id", primary_key=True)


class UserBase(SQLModel):
    username: str = Field(index=True, nullable=False, unique=True)


class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    password: str = Field(nullable=False)
    avatar: str | None = Field(default=None)
    disabled: bool | None = None
    groups: list["Group"] = Relationship(
        back_populates="members",
        link_model=UserGroupLink,
    )


class UserPublic(UserBase):
    id: int


class UserPublicAvatar(UserPublic):
    avatar: str | None


class GroupBase(SQLModel):
    name: str = Field(index=True, nullable=False)
    owner_id: int | None = Field(foreign_key="user.id")
    # owner: "User" = Relationship()
    private: bool = Field(default=False)
    # last_message_id: int | None = Field(default=None, foreign_key="message.id")


class Group(GroupBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    members: list["User"] = Relationship(
        back_populates="groups",
        link_model=UserGroupLink,
    )
    owner: "User" = Relationship()
    last_message: Message | None = Relationship(
        sa_relationship_kwargs={
            "order_by": "desc(Message.at)",
            "viewonly": True,
            "uselist": False,
        },
    )


class MessagePublic(MessageBase):
    id: int
    author: UserPublic
    at: datetime


class GroupPublic(GroupBase):
    id: int
    owner: UserPublic | None = None
    members: list[UserPublic] | None = []
    # messages: list[Message] | None = None
    last_message: MessagePublic | None = None


class LoginResponse(Token):
    username: str
    avatar: str | None = None
    disabled: bool | None = None


DB_URL = "postgresql://postgres:postgres@postgres:5432/postgres"

engine = create_engine(DB_URL, echo=True)


def create_db_and_tables():
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the ML model
    create_db_and_tables()
    user = create_user(User(username="test", password="test"))
    my_id1 = user.id
    user2 = create_user(User(username="test2", password="test"))
    create_user(User(username="test3", password="test"))
    create_user(User(username="test4", password="test"))
    create_user(User(username="test5", password="test"))
    create_user(User(username="test6", password="test"))
    create_user(User(username="test7", password="test"))
    create_user(User(username="test8", password="test"))
    my_id2 = user2.id
    group = await create_group(
        CreateGroupBody(name="Test Group", members=[
                        user2.id], private=True), user
    )

    for i in range(20):
        send_message_to_group(
            group.id, "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", my_id1
        )
        send_message_to_group(
            group.id,
            "Fusce vitae magna augue. Morbi ut ligula sollicitudin, pellentesque est vitae, pellentesque magna. In hac habitasse platea dictumst.",
            my_id2,
        )
        send_message_to_group(group.id, "Vivamus dictum ligula ante.", my_id2)
        send_message_to_group(
            group.id, "Morbi id arcu sit amet eros porttitor bibendum.", my_id1
        )
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


def create_avatar(initials, size=256, bgcolor=None, textcolor=None):
    img_size = (size, size)
    font_size = size / 2

    if not bgcolor:
        bgcolor = distinctipy.get_random_color(pastel_factor=0.5)

    if not textcolor:
        textcolor = distinctipy.get_text_color(bgcolor)

    img = Image.new("RGB", img_size, color=distinctipy.get_rgb256(bgcolor))
    draw = ImageDraw.Draw(img)

    # Load the default font with a custom size
    font = ImageFont.load_default(size=font_size)

    draw.text(
        (size / 2, size / 2),
        text=initials,
        fill=distinctipy.get_rgb256(textcolor),
        font=font,
        anchor="mm",
    )

    return img


# Convert Image to Base64
def im_2_b64(image: Image):
    buff = BytesIO()
    image.save(buff, format="JPEG")
    return base64.b64encode(buff.getvalue()).decode()


@app.post("/users/")
def create_user(user: User):
    user.password = get_password_hash(user.password)
    user.avatar = im_2_b64(create_avatar(user.username[0].upper()))
    with Session(engine) as session:
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


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


@app.get("/users/", response_model=list[UserPublicAvatar])
async def read_users(current_user: Annotated[User, Depends(get_current_user)], q: str | None = None):
    with Session(engine) as session:
        statement = select(User).where(User.id != current_user.id)
        if q:
            statement = statement.where(
                col(User.username).contains(q))
        else:
            users = session.exec(statement).all()
        return users


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


@app.post("/register/")
async def register(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    with Session(engine) as session:
        statement = select(User).where(User.username == form_data.username)
        user = session.exec(statement).first()
        if user is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists",
            )

    user = User(username=form_data.username, password=form_data.password)
    user = create_user(user)
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


class CreateGroupBody(BaseModel):
    name: str
    members: list[int]
    private: bool = False


@app.post("/groups/")
async def create_group(
    group: CreateGroupBody,
    current_user: User = Depends(get_current_user),
):
    if group.private and len(group.members) > 1:
        raise HTTPException(
            status_code=400,
            detail="Private group must have exactly two members",
        )

    with Session(engine) as session:
        members = session.exec(select(User).where(
            User.id.in_(group.members))).all()

        members.append(current_user)

        group = Group(
            name=group.name,
            owner_id=current_user.id,
            private=group.private,
            members=members,
        )

        session.add(group)
        session.commit()
        session.refresh(group)

        return group


@app.get("/groups/test", response_model=list[GroupPublic])
async def test_groups():
    with Session(engine) as session:
        statement = select(Group).options(
            joinedload(Group.owner), joinedload(Group.members)
        )

        return session.exec(statement).unique().all()


@app.get("/groups/", response_model=list[GroupPublic])
async def list_groups(
    current_user: User = Depends(get_current_user),
):
    with Session(engine) as session:
        statement = (
            select(Group)
            .join(UserGroupLink)
            .options(
                joinedload(Group.owner),
                joinedload(Group.members),
                joinedload(Group.last_message).joinedload(
                    Message.author, innerjoin=True
                ),
            )
            .filter(UserGroupLink.user_id == current_user.id)
        )

        rows = session.exec(statement).unique().all()
        return rows


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


@app.get("/groups/{group_id}/members", response_model=list[UserPublicAvatar])
async def get_group_members(group_id: int):
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        return group.members


def send_message_to_group(
    group_id: int, message_content: str, sender_id: int
) -> MessagePublic:
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Create the message
        message = Message(
            content=message_content, author_id=sender_id, group_id=group_id
        )
        session.add(message)
        session.commit()
        session.refresh(message.author)

        return message


class SendMessageBody(BaseModel):
    message_content: str


@app.post("/groups/{group_id}/messages", response_model=MessagePublic)
async def send_message(
    group_id: int,
    content: SendMessageBody,
    current_user: User = Depends(get_current_user),
):
    return send_message_to_group(group_id, content.message_content, current_user.id)


@app.get("/groups/{group_id}/messages", response_model=list[MessagePublic])
async def get_group_messages(group_id: int, limit: int = 10):
    limit = min(limit, 100)
    with Session(engine) as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Fetch the messages for the group with the specified limit
        messages = session.exec(
            select(Message)
            .options(joinedload(Message.author))
            .where(Message.group_id == group_id)
            .order_by(Message.id.desc())
            .limit(limit),
        ).all()

        return messages
