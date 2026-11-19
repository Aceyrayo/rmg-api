from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional

# 1. SETUP DATABASE
SQLALCHEMY_DATABASE_URL = "sqlite:///./rmg_database.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. DEFINE TABLES
class MessageDB(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    message = Column(String)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="client")
    # ENTERPRISE FIELDS
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String)
    company_name = Column(String)
    job_title = Column(String)

Base.metadata.create_all(bind=engine)

# 3. SETUP SECURITY
SECRET_KEY = "super-secret-rmg-key-change-this-later"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    db.close()
    if user is None:
        raise credentials_exception
    return user

# 4. SETUP API
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ContactForm(BaseModel):
    name: str
    email: str
    message: str

class UserRegister(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    company_name: str
    job_title: str
    username: str
    password: str

@app.get("/")
def read_root():
    return {"message": "RMG API is running perfectly."}

@app.post("/api/register")
def register_user(user: UserRegister):
    db = SessionLocal()
    try:
        if db.query(UserDB).filter(UserDB.username == user.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        if db.query(UserDB).filter(UserDB.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        hashed_pw = get_password_hash(user.password)
        new_user = UserDB(
            username=user.username, 
            hashed_password=hashed_pw, 
            role="client",
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            phone=user.phone,
            company_name=user.company_name,
            job_title=user.job_title
        )
        db.add(new_user)
        db.commit()
        return {"message": "User registered successfully"}
    finally:
        db.close()

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        access_token = create_access_token(data={"sub": user.username, "role": user.role})
        return {"access_token": access_token, "token_type": "bearer", "role": user.role, "first_name": user.first_name}
    finally:
        db.close()

@app.get("/api/messages")
def get_all_messages(current_user: UserDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    db = SessionLocal()
    try:
        return db.query(MessageDB).order_by(MessageDB.id.desc()).all()
    finally:
        db.close()

@app.get("/api/setup-admin")
def setup_admin():
    db = SessionLocal()
    try:
        if db.query(UserDB).filter(UserDB.username == "admin").first():
            return {"message": "Admin already exists"}
        hashed_pw = get_password_hash("password123")
        new_admin = UserDB(
            username="admin", hashed_password=hashed_pw, role="admin",
            first_name="System", last_name="Admin", 
            email="admin@rmgtechnologies.com", phone="+1 555 000 0000",
            company_name="RMG", job_title="Administrator"
        )
        db.add(new_admin)
        db.commit()
        return {"message": "Admin created!"}
    finally:
        db.close()