import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import Column, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./blog.db")
extra = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=extra)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(20), default="user")
class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# Schemas
class Credentials(BaseModel):
    username: str
    password: str
class PostIn(BaseModel):
    title: str
    content: str
class PostOut(PostIn):
    id: int
    author_id: int | None = None
    model_config = {"from_attributes": True}
# Security
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
TOKEN_MINUTES = int(os.getenv("TOKEN_MINUTES", "30"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.username == data["sub"]).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user
def admin_only(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user
def find_post(post_id: int, db: Session) -> Post:
    post = db.get(Post, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return post
# Application
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(User).filter(User.username == "admin").first():
        password = os.getenv("ADMIN_PASSWORD", "admin123")
        db.add(User(username="admin", password_hash=hash_password(password), role="admin"))
        db.commit()
    db.close()
    yield
app = FastAPI(title="Blog API", lifespan=lifespan)
# API Endpoints
@app.get("/")
def home():
    return {"message": "Blog API is running. Open /docs to test it."}
@app.post("/register", status_code=201)
def register(data: Credentials, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    db.add(User(username=data.username, password_hash=hash_password(data.password)))
    db.commit()
    return {"message": "User registered"}
@app.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if user is None or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {
        "access_token": create_token(user.username, user.role),
        "token_type": "bearer"
    }
@app.get("/posts", response_model=list[PostOut])
def list_posts(db: Session = Depends(get_db)):
    return db.query(Post).all()
@app.get("/posts/{post_id}", response_model=PostOut)
def read_post(post_id: int, db: Session = Depends(get_db)):
    return find_post(post_id, db)
@app.post("/posts", response_model=PostOut, status_code=201)
def create_post(data: PostIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    post = Post(title=data.title, content=data.content, author_id=user.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post
@app.put("/posts/{post_id}", response_model=PostOut)
def update_post(post_id: int, data: PostIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    post = find_post(post_id, db)
    if post.author_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not your post")
    post.title = data.title
    post.content = data.content
    db.commit()
    db.refresh(post)
    return post
@app.delete("/posts/{post_id}")
def delete_post(post_id: int, db: Session = Depends(get_db), admin: User = Depends(admin_only)):
    post = find_post(post_id, db)
    db.delete(post)
    db.commit()
    return {"message": "Post deleted"}







