import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pwdlib import PasswordHash
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    selectinload,
    sessionmaker,
)


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


DATABASE_URL = normalize_database_url(
    os.getenv("DATABASE_URL", "sqlite:///./music.db")
)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine_options = (
    {"connect_args": {"check_same_thread": False}}
    if DATABASE_URL.startswith("sqlite")
    else {}
)
engine = create_engine(DATABASE_URL, **engine_options)

if engine.dialect.name == "sqlite":
    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(
        dbapi_connection: object, _connection_record: object
    ) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
legacy_password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)


class Song(Base):
    __tablename__ = "songs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    artist: Mapped[str] = mapped_column(String, nullable=False)
    genre: Mapped[str] = mapped_column(String, nullable=False)
    youtube_url: Mapped[str] = mapped_column(String, nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner: Mapped[User | None] = relationship()

    @property
    def owner_username(self) -> str | None:
        return self.owner.username if self.owner is not None else None


class SongLike(Base):
    __tablename__ = "song_likes"
    __table_args__ = (UniqueConstraint("user_id", "song_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    song_id: Mapped[int] = mapped_column(
        ForeignKey("songs.id", ondelete="CASCADE"), nullable=False
    )


Base.metadata.create_all(bind=engine)
if "owner_id" not in {column["name"] for column in inspect(engine).get_columns("songs")}:
    with engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE songs ADD COLUMN owner_id INTEGER REFERENCES users(id)")
        )

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def serve_frontend() -> FileResponse:
    return FileResponse(Path(__file__).with_name("index.html"))


class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class SongCreate(BaseModel):
    title: str
    artist: str
    genre: str
    youtube_url: str


class SongResponse(SongCreate):
    id: int
    owner_username: str | None
    like_count: int = 0
    liked_by_me: bool = False

    model_config = ConfigDict(from_attributes=True)


class SongLikeResponse(BaseModel):
    song_id: int
    like_count: int
    liked_by_me: bool


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return jwt.encode(
        {"sub": username, "exp": expires_at},
        SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        username = payload.get("sub")
        if not isinstance(username, str):
            raise unauthorized
    except jwt.InvalidTokenError:
        raise unauthorized

    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise unauthorized
    return user


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)) -> dict[str, str]:
    if db.scalar(select(User).where(User.username == user_data.username)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered",
        )

    user = User(
        username=user_data.username,
        hashed_password=password_context.hash(user_data.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered",
        )
    return {"message": "User registered successfully"}


@app.post("/api/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.scalar(select(User).where(User.username == user_data.username))
    if user is None:
        verified_password = False
    elif user.hashed_password.startswith("$argon2"):
        verified_password = legacy_password_hash.verify(
            user_data.password, user.hashed_password
        )
        if verified_password:
            user.hashed_password = password_context.hash(user_data.password)
            db.commit()
    else:
        verified_password = password_context.verify(
            user_data.password, user.hashed_password
        )

    if not verified_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "access_token": create_access_token(user.username),
        "token_type": "bearer",
    }


@app.get("/api/songs", response_model=list[SongResponse])
def list_songs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SongResponse]:
    like_count = (
        select(func.count(SongLike.id))
        .where(SongLike.song_id == Song.id)
        .correlate(Song)
        .scalar_subquery()
    )
    liked_by_me = (
        select(SongLike.id)
        .where(
            SongLike.song_id == Song.id,
            SongLike.user_id == current_user.id,
        )
        .exists()
    )
    rows = db.execute(
        select(Song, like_count.label("like_count"), liked_by_me.label("liked_by_me"))
        .options(selectinload(Song.owner))
        .order_by(Song.id)
    ).all()
    return [
        SongResponse.model_validate(song).model_copy(
            update={"like_count": count, "liked_by_me": liked}
        )
        for song, count, liked in rows
    ]


@app.post("/api/songs/{song_id}/like", response_model=SongLikeResponse)
def toggle_song_like(
    song_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SongLikeResponse:
    if db.get(Song, song_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Song not found",
        )

    existing_like = db.scalar(
        select(SongLike).where(
            SongLike.song_id == song_id,
            SongLike.user_id == current_user.id,
        )
    )
    if existing_like is not None:
        db.delete(existing_like)
    else:
        db.add(SongLike(song_id=song_id, user_id=current_user.id))

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.scalar(
            select(SongLike.id).where(
                SongLike.song_id == song_id,
                SongLike.user_id == current_user.id,
            )
        ) is None:
            raise

    like_count = db.scalar(
        select(func.count(SongLike.id)).where(SongLike.song_id == song_id)
    )
    liked_by_me = (
        db.scalar(
            select(SongLike.id).where(
                SongLike.song_id == song_id,
                SongLike.user_id == current_user.id,
            )
        )
        is not None
    )
    return SongLikeResponse(
        song_id=song_id,
        like_count=like_count or 0,
        liked_by_me=liked_by_me,
    )


@app.post(
    "/api/songs",
    response_model=SongResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_song(
    song_data: SongCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Song:
    song = Song(**song_data.model_dump(), owner=current_user)
    db.add(song)
    db.commit()
    db.refresh(song)
    return song


@app.put("/api/songs/{song_id}", response_model=SongResponse)
def update_song(
    song_id: int,
    song_data: SongCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Song:
    song = db.get(Song, song_id)
    if song is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Song not found",
        )
    if song.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update songs you created",
        )

    for field, value in song_data.model_dump().items():
        setattr(song, field, value)
    db.commit()
    db.refresh(song)
    return song


@app.delete("/api/songs/{song_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_song(
    song_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    song = db.get(Song, song_id)
    if song is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Song not found",
        )
    if song.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete songs you created",
        )

    db.delete(song)
    db.commit()
