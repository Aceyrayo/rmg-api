from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. SETUP DATABASE
# This creates a file called "rmg_database.db" in your folder
SQLALCHEMY_DATABASE_URL = "sqlite:///./rmg_database.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. DEFINE THE TABLE (The Filing Cabinet)
class MessageDB(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    message = Column(String)

# Create the table if it doesn't exist yet
Base.metadata.create_all(bind=engine)

# 3. SETUP API
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "http://localhost:4321", "http://127.0.0.1:4321"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ContactForm(BaseModel):
    name: str
    email: str
    message: str

@app.get("/")
def read_root():
    return {"message": "RMG API is running perfectly."}

# 4. THE UPGRADED WAITER
@app.post("/api/contact")
def handle_contact(form: ContactForm):
    # Open a session with the database
    db = SessionLocal()
    
    try:
        # Create a new row in our database table
        new_message = MessageDB(
            name=form.name, 
            email=form.email, 
            message=form.message
        )
        
        # Add it and save it permanently
        db.add(new_message)
        db.commit()
        db.refresh(new_message)
        
        print(f"\n--- SAVED TO DATABASE ---")
        print(f"ID: {new_message.id} | From: {new_message.name}")
        print(f"-------------------------\n")
        
        return {"status": "success", "message": "Saved!"}
    
    finally:
        # Always close the database connection when done
        db.close()
# Add this at the very bottom of main.py
@app.get("/api/messages")
def get_all_messages():
    db = SessionLocal()
    try:
        # Go into the database and grab all messages, newest first
        messages = db.query(MessageDB).order_by(MessageDB.id.desc()).all()
        return messages
    finally:
        db.close()