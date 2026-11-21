from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
import random

# EMAIL IMPORTS
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

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
    # NEW EMAIL VERIFICATION FIELDS
    is_verified = Column(Boolean, default=False)
    verification_code = Column(String, nullable=True)

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

# 4. SETUP EMAIL CONFIG
conf = ConnectionConfig(
    MAIL_USERNAME = "rmgtechnologiesincgroup@gmail.com", 
    MAIL_PASSWORD = "ecpe gkef wqok ezch", # NOT your normal password!
    MAIL_FROM = "rmgtechnologiesincgroup@gmail.com",
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

# 5. SETUP API
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4321", 
        "http://127.0.0.1:4321",
        "https://rmg-site.vercel.app" # <--- Your Vercel URL
    ], 
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

class VerifyEmail(BaseModel):
    email: EmailStr
    code: str

# --- ROUTES ---
@app.get("/")
def read_root():
    return {"message": "RMG API is running perfectly."}

@app.post("/api/contact")
def handle_contact(form: ContactForm):
    db = SessionLocal()
    try:
        new_message = MessageDB(name=form.name, email=form.email, message=form.message)
        db.add(new_message)
        db.commit()
        return {"status": "success", "message": "Message saved!"}
    finally:
        db.close()

@app.post("/api/register")
async def register_user(user: UserRegister):
    db = SessionLocal()
    try:
        if db.query(UserDB).filter(UserDB.username == user.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        if db.query(UserDB).filter(UserDB.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        hashed_pw = get_password_hash(user.password)
        
        # GENERATE 6-DIGIT CODE
        code = str(random.randint(100000, 999999))
        
        new_user = UserDB(
            username=user.username, 
            hashed_password=hashed_pw, 
            role="client",
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            phone=user.phone,
            company_name=user.company_name,
            job_title=user.job_title,
            is_verified=False,
            verification_code=code
        )
        db.add(new_user)
        db.commit()

        # SEND THE EMAIL
        html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 10px;">
            <h2 style="color: #0f172a;">Welcome to RMG Technologies</h2>
            <p>Hello {user.first_name},</p>
            <p>Thank you for signing up. To activate your enterprise account, please use the following 6-digit security code:</p>
            <h1 style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center; letter-spacing: 5px; color: #2563eb;">{code}</h1>
            <p>If you did not request this, please ignore this email.</p>
        </div>
        """
        message = MessageSchema(
            subject="Your RMG Security Code",
            recipients=[user.email],
            body=html,
            subtype=MessageType.html
        )
        
        fm = FastMail(conf)
        await fm.send_message(message)

        return {"message": "User registered. Please check your email for the verification code."}
    finally:
        db.close()

@app.post("/api/verify-email")
def verify_email(data: VerifyEmail):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_verified:
            return {"message": "Account already verified. You can log in."}
        
        if user.verification_code != data.code:
            raise HTTPException(status_code=400, detail="Invalid verification code")
        
        user.is_verified = True
        user.verification_code = None
        db.commit()
        return {"message": "Account verified successfully!"}
    finally:
        db.close()

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        
        # CHECK IF VERIFIED
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Please verify your email address before logging in.")
        
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
            company_name="RMG", job_title="Administrator",
            is_verified=True # ADMIN BYPASSES VERIFICATION
        )
        db.add(new_admin)
        db.commit()
        return {"message": "Admin created!"}
    finally:
        db.close()

# --- PUBLIC STATS ROUTE ---
@app.get("/api/stats")
def get_stats():
    db = SessionLocal()
    try:
        user_count = db.query(UserDB).count()
        return {
            "global_users": user_count,
            "uptime": "99.99%",
            "latency": "< 10ms"
        }
    finally:
        db.close()


import os

@app.get("/api/reset-db")
def reset_database():
    # THIS IS A DANGEROUS ROUTE (Only use for testing)
    db_path = "./rmg_database.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        # Recreate tables
        Base.metadata.create_all(bind=engine)
        return {"message": "Database cleared and recreated."}
    return {"message": "No database found to clear."}