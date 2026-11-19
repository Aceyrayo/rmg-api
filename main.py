from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

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
    role = Column(String, default="client") # NEW: "admin" or "client"

Base.metadata.create_all(bind=engine)

# 3. SETUP SECURITY
SECRET_KEY = "super-secret-rmg-key-change-this-later"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

# Dependency to get current user from token
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

# --- MODELS ---
class ContactForm(BaseModel):
    name: str
    email: str
    message: str

class UserRegister(BaseModel):
    username: str
    password: str

# --- PUBLIC ROUTES ---
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
        return {"status": "success"}
    finally:
        db.close()

# --- AUTH ROUTES ---
@app.post("/api/register")
def register_user(user: UserRegister):
    db = SessionLocal()
    try:
        # Check if user exists
        existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Create new client user
        hashed_pw = get_password_hash(user.password)
        new_user = UserDB(username=user.username, hashed_password=hashed_pw, role="client")
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
        
        # Put their role inside the token!
        access_token = create_access_token(data={"sub": user.username, "role": user.role})
        return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    finally:
        db.close()

# --- PROTECTED ROUTES ---
@app.get("/api/messages")
def get_all_messages(current_user: UserDB = Depends(get_current_user)):
    # AUTHORIZATION CHECK: Only admins can read messages!
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    db = SessionLocal()
    try:
        messages = db.query(MessageDB).order_by(MessageDB.id.desc()).all()
        return messages
    finally:
        db.close()

# --- ONE-TIME SETUP ROUTE ---
@app.get("/api/setup-admin")
def setup_admin():
    db = SessionLocal()
    try:
        admin = db.query(UserDB).filter(UserDB.username == "admin").first()
        if admin:
            return {"message": "Admin already exists"}
        
        hashed_pw = get_password_hash("password123")
        new_admin = UserDB(username="admin", hashed_password=hashed_pw, role="admin")
        db.add(new_admin)
        db.commit()
        return {"message": "Admin created! Username: admin, Password: password123"}
    finally:
        db.close()