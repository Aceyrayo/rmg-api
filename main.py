from fastapi import FastAPI, Depends, HTTPException, status, Request
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
import time
import os
import httpx
from html import escape

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
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String)
    company_name = Column(String)
    job_title = Column(String)
    is_verified = Column(Boolean, default=False)
    verification_code = Column(String, nullable=True)

class TicketDB(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    subject = Column(String)
    category = Column(String)
    description = Column(String)
    status = Column(String, default="Open")
    created_at = Column(String)

class InvoiceDB(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    invoice_number = Column(String)
    amount = Column(String)
    date = Column(String)

class AuditDB(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String)
    action = Column(String)
    detail = Column(String)
    created_at = Column(String)

Base.metadata.create_all(bind=engine)

# 3. SETUP SECURITY
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-rmg-key-change-this-later")  # set SECRET_KEY in Render env
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
    to_encode.update({"exp": expire, "iat": int(time.time())})
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
    if payload.get("iat", 0) < REVOKED.get(username, 0):  # sessions revoked by an admin
        raise HTTPException(status_code=401, detail="Session revoked")
    return user

# 4. SETUP EMAIL (Resend API)
RESEND_API_KEY = os.getenv("RESEND_API_KEY")

async def send_verification_email(email: str, code: str, name: str):
    html_content = f"""
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 10px;">
        <h2 style="color: #0f172a;">Welcome to RMG Technologies</h2>
        <p>Hello {name},</p>
        <p>Thank you for signing up. To activate your enterprise account, please use the following 6-digit security code:</p>
        <h1 style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center; letter-spacing: 5px; color: #2563eb;">{code}</h1>
        <p>If you did not request this, please ignore this email.</p>
    </div>
    """

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": "RMG Technologies <onboarding@resend.dev>",
                "to": [email],
                "subject": "Your RMG Security Code",
                "html": html_content
            }
        )
        
        if response.status_code != 200:
            print(f"Failed to send email: {response.text}")
            raise HTTPException(status_code=500, detail="Failed to send verification email")

# 5. SETUP API
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4321", 
        "http://127.0.0.1:4321",
        "https://rmg-site.vercel.app" # <--- Ensure this matches your Vercel URL
    ], 
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- PYDANTIC MODELS ---
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

class ProfileUpdate(BaseModel):
    first_name: str
    last_name: str
    phone: str
    company_name: str
    job_title: str

class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str

class DeleteAccountRequest(BaseModel):
    password: str

class TicketCreate(BaseModel):
    subject: str
    category: str
    description: str

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

        await send_verification_email(user.email, code, user.first_name)

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
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            audit(db, form_data.username, "LOGIN_FAILED", client_ip(request))
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Please verify your email address before logging in.")
        
        access_token = create_access_token(data={"sub": user.username, "role": user.role})
        audit(db, user.username, "LOGIN", client_ip(request))
        
        return {
            "access_token": access_token, 
            "token_type": "bearer", 
            "role": user.role, 
            "first_name": user.first_name,
            "email": user.email 
        }
    finally:
        db.close()

# --- PROFILE ROUTES ---
@app.get("/api/profile")
def get_profile(current_user: UserDB = Depends(get_current_user)):
    return {
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "email": current_user.email,
        "phone": current_user.phone,
        "company_name": current_user.company_name,
        "job_title": current_user.job_title
    }

@app.put("/api/profile")
def update_profile(profile: ProfileUpdate, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.id == current_user.id).first()
        user.first_name = profile.first_name
        user.last_name = profile.last_name
        user.phone = profile.phone
        user.company_name = profile.company_name
        user.job_title = profile.job_title
        db.commit()
        return {"message": "Profile updated successfully!"}
    finally:
        db.close()

@app.put("/api/change-password")
def change_password(data: PasswordUpdate, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.id == current_user.id).first()
        if not verify_password(data.old_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect current password")
        user.hashed_password = get_password_hash(data.new_password)
        db.commit()
        return {"message": "Password updated successfully!"}
    finally:
        db.close()

@app.delete("/api/profile")
def delete_profile(data: DeleteAccountRequest, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.id == current_user.id).first()
        if not verify_password(data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect password. Account not deleted.")
        db.delete(user)
        db.commit()
        return {"message": "Account deleted successfully"}
    finally:
        db.close()

# --- SUPPORT TICKETS ROUTES ---
@app.post("/api/tickets")
def create_ticket(ticket: TicketCreate, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        new_ticket = TicketDB(
            user_id=current_user.id,
            subject=ticket.subject,
            category=ticket.category,
            description=ticket.description,
            status="Open",
            created_at=datetime.now().strftime("%b %d, %Y")
        )
        db.add(new_ticket)
        db.commit()
        return {"message": "Ticket submitted successfully"}
    finally:
        db.close()

@app.get("/api/tickets")
def get_tickets(current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return db.query(TicketDB).filter(TicketDB.user_id == current_user.id).order_by(TicketDB.id.desc()).all()
    finally:
        db.close()

# --- BILLING INVOICES ROUTES ---
@app.get("/api/invoices")
def get_invoices(current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        invoices = db.query(InvoiceDB).filter(InvoiceDB.user_id == current_user.id).all()
        # If no invoices, create a dummy one for testing
        if not invoices:
            dummy = InvoiceDB(user_id=current_user.id, invoice_number="RMG-2026-001", amount="$299.00", date="Oct 28, 2026")
            db.add(dummy)
            db.commit()
            invoices = [dummy]
        return invoices
    finally:
        db.close()

# --- ADMIN ROUTES ---
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
        admin_pw = os.getenv("ADMIN_PASSWORD")
        if not admin_pw:
            raise HTTPException(status_code=503, detail="Set ADMIN_PASSWORD env var first")
        hashed_pw = get_password_hash(admin_pw)
        new_admin = UserDB(
            username="admin", hashed_password=hashed_pw, role="admin",
            first_name="System", last_name="Admin", 
            email="admin@rmgtechnologies.com", phone="+1 555 000 0000",
            company_name="RMG", job_title="Administrator",
            is_verified=True
        )
        db.add(new_admin)
        db.commit()
        return {"message": "Admin created!"}
    finally:
        db.close()

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


# ======================= ADMIN API =======================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def require_admin(current_user: UserDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def audit(db, actor: str, action: str, detail: str = ""):
    db.add(AuditDB(actor=actor, action=action, detail=detail,
                   created_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()

async def send_email(to: str, subject: str, html: str) -> bool:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": "RMG Technologies <onboarding@resend.dev>", "to": [to], "subject": subject, "html": html},
        )
        return r.status_code == 200

class UserAdminUpdate(BaseModel):
    role: Optional[str] = None
    is_verified: Optional[bool] = None

class TicketStatusUpdate(BaseModel):
    status: str

class InvoiceCreate(BaseModel):
    user_id: int
    invoice_number: str
    amount: str
    date: str

class BroadcastForm(BaseModel):
    subject: str
    body: str
    audience: str = "all"  # all | clients

@app.get("/api/admin/stats")
def admin_stats(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    return {
        "users": db.query(UserDB).count(),
        "verified": db.query(UserDB).filter(UserDB.is_verified == True).count(),
        "open_tickets": db.query(TicketDB).filter(TicketDB.status == "Open").count(),
        "messages": db.query(MessageDB).count(),
        "invoices": db.query(InvoiceDB).count(),
    }

@app.get("/api/admin/users")
def admin_users(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    keys = ("id", "username", "first_name", "last_name", "email", "phone", "company_name", "job_title", "role", "is_verified")
    return [{k: getattr(u, k) for k in keys} for u in db.query(UserDB).order_by(UserDB.id.desc()).all()]

@app.patch("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, data: UserAdminUpdate, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if data.role is not None:
        if data.role not in ("admin", "client"):
            raise HTTPException(status_code=400, detail="Invalid role")
        if u.id == admin.id and data.role != "admin":
            raise HTTPException(status_code=400, detail="You cannot remove your own admin role")
        u.role = data.role
    if data.is_verified is not None:
        u.is_verified = data.is_verified
    db.commit()
    audit(db, admin.username, "USER_UPDATE", f"{u.email}: {data.dict(exclude_none=True)}")
    return {"message": "User updated"}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if u.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account here")
    email = u.email
    db.delete(u)
    db.commit()
    audit(db, admin.username, "USER_DELETE", email)
    return {"message": "User deleted"}

@app.get("/api/admin/tickets")
def admin_tickets(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    emails = {u.id: u.email for u in db.query(UserDB).all()}
    return [{"id": t.id, "user_email": emails.get(t.user_id, "deleted user"), "subject": t.subject,
             "category": t.category, "description": t.description, "status": t.status, "created_at": t.created_at}
            for t in db.query(TicketDB).order_by(TicketDB.id.desc()).all()]

@app.patch("/api/admin/tickets/{ticket_id}")
def admin_update_ticket(ticket_id: int, data: TicketStatusUpdate, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    if data.status not in ("Open", "In Progress", "Resolved", "Closed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    t = db.get(TicketDB, ticket_id)
    if not t:
        raise HTTPException(status_code=404, detail="Ticket not found")
    t.status = data.status
    db.commit()
    audit(db, admin.username, "TICKET_STATUS", f"#{t.id} -> {data.status}")
    return {"message": "Ticket updated"}

@app.delete("/api/messages/{message_id}")
def admin_delete_message(message_id: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    m = db.get(MessageDB, message_id)
    if not m:
        raise HTTPException(status_code=404, detail="Message not found")
    db.delete(m)
    db.commit()
    audit(db, admin.username, "MESSAGE_DELETE", f"#{message_id}")
    return {"message": "Message deleted"}

@app.get("/api/admin/invoices")
def admin_invoices(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    emails = {u.id: u.email for u in db.query(UserDB).all()}
    return [{"id": i.id, "user_email": emails.get(i.user_id, "deleted user"), "invoice_number": i.invoice_number,
             "amount": i.amount, "date": i.date} for i in db.query(InvoiceDB).order_by(InvoiceDB.id.desc()).all()]

@app.post("/api/admin/invoices")
def admin_create_invoice(data: InvoiceCreate, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    if not db.get(UserDB, data.user_id):
        raise HTTPException(status_code=404, detail="User not found")
    db.add(InvoiceDB(user_id=data.user_id, invoice_number=data.invoice_number, amount=data.amount, date=data.date))
    db.commit()
    audit(db, admin.username, "INVOICE_CREATE", f"{data.invoice_number} ({data.amount})")
    return {"message": "Invoice created"}

@app.delete("/api/admin/invoices/{invoice_id}")
def admin_delete_invoice(invoice_id: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    inv = db.get(InvoiceDB, invoice_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    db.delete(inv)
    db.commit()
    audit(db, admin.username, "INVOICE_DELETE", inv.invoice_number)
    return {"message": "Invoice deleted"}

@app.post("/api/admin/broadcast")
async def admin_broadcast(f: BroadcastForm, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    q = db.query(UserDB).filter(UserDB.is_verified == True)
    if f.audience == "clients":
        q = q.filter(UserDB.role == "client")
    html = "<div style='font-family:sans-serif;max-width:600px;margin:auto;line-height:1.6'>" + escape(f.body).replace("\n", "<br>") + "</div>"
    sent = 0
    for u in q.all():
        if await send_email(u.email, f.subject, html):
            sent += 1
    audit(db, admin.username, "BROADCAST", f"'{f.subject}' -> {sent} recipients")
    return {"message": f"Broadcast delivered to {sent} recipient(s)", "sent": sent}

@app.get("/api/admin/audit")
def admin_audit(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    return [{"id": a.id, "actor": a.actor, "action": a.action, "detail": a.detail, "created_at": a.created_at}
            for a in db.query(AuditDB).order_by(AuditDB.id.desc()).limit(500).all()]



# ======================= PLATFORM / OPS API =======================
import json, secrets, hashlib
from collections import deque, Counter
from fastapi.responses import JSONResponse
from sqlalchemy import Text, select

class RecordDB(Base):
    """Generic admin-managed records: engines, protocols, nodes, updates, rollbacks, subscriptions,
    transactions, payouts, announcements, firewall rules, webhooks, webhook logs, API keys, revocations."""
    __tablename__ = "records"
    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String, index=True)
    data = Column(Text)
    created_at = Column(String)

Base.metadata.create_all(bind=engine)

KINDS = {"trading_engine", "defense_protocol", "enterprise_node", "update", "rollback", "subscription",
         "transaction", "payout", "announcement", "firewall", "webhook", "webhook_log", "key", "revocation"}
NO_GENERIC_CREATE = {"key", "revocation", "webhook_log"}
START_TIME = time.time()
REQ_LOG = deque(maxlen=1000)
BLOCKED_IPS: set = set()
REVOKED: dict = {}

def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")

def rec_out(r):
    d = json.loads(r.data or "{}")
    d.pop("hash", None)
    d.update(id=r.id, kind=r.kind, created_at=r.created_at)
    return d

def refresh_security(db):
    BLOCKED_IPS.clear()
    REVOKED.clear()
    for r in db.query(RecordDB).filter(RecordDB.kind.in_(["firewall", "revocation"])).all():
        d = json.loads(r.data or "{}")
        if r.kind == "firewall" and d.get("action") == "Block" and d.get("status", "Active") == "Active" and d.get("ip"):
            BLOCKED_IPS.add(d["ip"].strip())
        if r.kind == "revocation":
            REVOKED[d["username"]] = max(REVOKED.get(d["username"], 0), d["at"])

_boot = SessionLocal(); refresh_security(_boot); _boot.close()

@app.middleware("http")
async def monitor(request: Request, call_next):
    """Request logging, firewall enforcement and error capture."""
    if request.method == "OPTIONS":
        return await call_next(request)
    ip, t0, err = client_ip(request), time.time(), ""
    if ip in BLOCKED_IPS:
        resp, err = JSONResponse({"detail": "Blocked by firewall"}, status_code=403, headers={"Access-Control-Allow-Origin": "*"}), "firewall"
    else:
        try:
            resp = await call_next(request)
        except Exception as e:
            err = repr(e)[:300]
            resp = JSONResponse({"detail": "Internal server error"}, status_code=500)
    REQ_LOG.appendleft({"ts": time.time(), "time": now_str(), "method": request.method, "path": request.url.path,
                        "status": resp.status_code, "ms": round((time.time() - t0) * 1000), "ip": ip, "error": err})
    return resp

class RecordIn(BaseModel):
    data: dict

def _check_kind(kind):
    if kind not in KINDS:
        raise HTTPException(status_code=404, detail="Unknown record type")

def _guard_self_block(kind, data, request):
    if kind == "firewall" and data.get("action") == "Block" and data.get("status", "Active") == "Active" \
            and str(data.get("ip", "")).strip() == client_ip(request):
        raise HTTPException(status_code=400, detail="Refusing to block your own IP address")

@app.get("/api/admin/records/{kind}")
def list_records(kind: str, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    _check_kind(kind)
    return [rec_out(r) for r in db.query(RecordDB).filter(RecordDB.kind == kind).order_by(RecordDB.id.desc()).limit(500).all()]

@app.post("/api/admin/records/{kind}")
def create_record(kind: str, body: RecordIn, request: Request, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    _check_kind(kind)
    if kind in NO_GENERIC_CREATE:
        raise HTTPException(status_code=400, detail="Not allowed for this type")
    _guard_self_block(kind, body.data, request)
    r = RecordDB(kind=kind, data=json.dumps(body.data), created_at=now_str())
    db.add(r); db.commit()
    if kind == "firewall":
        refresh_security(db)
    audit(db, admin.username, f"{kind.upper()}_CREATE", str(body.data)[:200])
    return rec_out(r)

@app.patch("/api/admin/records/{kind}/{rid}")
def update_record(kind: str, rid: int, body: RecordIn, request: Request, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    _check_kind(kind)
    r = db.get(RecordDB, rid)
    if not r or r.kind != kind:
        raise HTTPException(status_code=404, detail="Record not found")
    d = json.loads(r.data or "{}"); d.update(body.data)
    _guard_self_block(kind, d, request)
    r.data = json.dumps(d); db.commit()
    if kind == "firewall":
        refresh_security(db)
    audit(db, admin.username, f"{kind.upper()}_UPDATE", f"#{rid} {str(body.data)[:150]}")
    return rec_out(r)

@app.delete("/api/admin/records/{kind}/{rid}")
def delete_record(kind: str, rid: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    _check_kind(kind)
    r = db.get(RecordDB, rid)
    if not r or r.kind != kind or kind == "revocation":
        raise HTTPException(status_code=404, detail="Record not found")
    db.delete(r); db.commit()
    if kind == "firewall":
        refresh_security(db)
    audit(db, admin.username, f"{kind.upper()}_DELETE", f"#{rid}")
    return {"message": "Deleted"}

class KeyIn(BaseModel):
    name: str
    scope: str = "read"

@app.post("/api/admin/keys")
def create_key(data: KeyIn, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    raw = "rmg_" + secrets.token_urlsafe(32)
    meta = {"name": data.name, "scope": data.scope, "prefix": raw[:12] + "…", "hash": hashlib.sha256(raw.encode()).hexdigest(), "status": "Active"}
    r = RecordDB(kind="key", data=json.dumps(meta), created_at=now_str())
    db.add(r); db.commit()
    audit(db, admin.username, "KEY_CREATE", f"{data.name} ({data.scope})")
    return {"key": raw, **rec_out(r)}  # raw key is shown ONCE; only its SHA-256 is stored

@app.post("/api/admin/webhooks/{rid}/test")
async def test_webhook(rid: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    r = db.get(RecordDB, rid)
    if not r or r.kind != "webhook":
        raise HTTPException(status_code=404, detail="Webhook not found")
    d = json.loads(r.data or "{}")
    t0, code, err = time.time(), 0, ""
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            code = (await c.post(d.get("url", ""), json={"event": "test", "source": "rmg", "at": now_str()})).status_code
    except Exception as e:
        err = str(e)[:200]
    log = {"webhook": d.get("name"), "url": d.get("url"), "event": "test", "status": code or "ERR",
           "ok": 200 <= code < 300, "ms": round((time.time() - t0) * 1000), "error": err}
    db.add(RecordDB(kind="webhook_log", data=json.dumps(log), created_at=now_str())); db.commit()
    audit(db, admin.username, "WEBHOOK_TEST", f"{d.get('name')} -> {code or 'ERR'}")
    return log

class RevokeIn(BaseModel):
    username: str

@app.get("/api/admin/sessions")
def admin_sessions(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    out = {}
    for a in db.query(AuditDB).filter(AuditDB.action.in_(["LOGIN", "LOGIN_FAILED"])).order_by(AuditDB.id.desc()).limit(500).all():
        u = out.setdefault(a.actor, {"username": a.actor, "last_login": "", "ip": "", "logins": 0, "failed": 0, "revoked_at": REVOKED.get(a.actor)})
        if a.action == "LOGIN":
            u["logins"] += 1
            if not u["last_login"]:
                u["last_login"], u["ip"] = a.created_at, a.detail
        else:
            u["failed"] += 1
    return list(out.values())

@app.post("/api/admin/sessions/revoke")
def revoke_sessions(data: RevokeIn, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    at = int(time.time())
    db.add(RecordDB(kind="revocation", data=json.dumps({"username": data.username, "at": at}), created_at=now_str())); db.commit()
    REVOKED[data.username] = at
    audit(db, admin.username, "SESSIONS_REVOKED", data.username)
    return {"message": f"All sessions for {data.username} revoked"}

@app.get("/api/admin/requests")
def admin_requests(errors: bool = False, limit: int = 500, admin: UserDB = Depends(require_admin)):
    rows = [r for r in REQ_LOG if (not errors or r["status"] >= 500 or r["error"])]
    return [{k: v for k, v in r.items() if k != "ts"} for r in rows[:min(limit, 1000)]]

@app.get("/api/admin/routes")
def admin_routes(admin: UserDB = Depends(require_admin)):
    out = []
    for rt in app.routes:
        path = getattr(rt, "path", "")
        if not path.startswith("/api") or not getattr(rt, "methods", None):
            continue
        prefix = path.split("{")[0]
        for m in sorted(rt.methods - {"HEAD", "OPTIONS"}):
            hits = [r for r in REQ_LOG if r["method"] == m and (r["path"] == path or ("{" in path and r["path"].startswith(prefix)))]
            out.append({"method": m, "path": path, "scope": "Admin" if path.startswith("/api/admin") or path in ("/api/messages",) else "Public / User",
                        "calls": len(hits), "errors": sum(1 for r in hits if r["status"] >= 400),
                        "avg_ms": round(sum(r["ms"] for r in hits) / len(hits)) if hits else 0})
    return out

@app.get("/api/admin/health")
def admin_health(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    recent = [r for r in REQ_LOG if time.time() - r["ts"] < 300]
    try:
        db_bytes = os.path.getsize("rmg_database.db")
    except OSError:
        db_bytes = 0
    return {"uptime_s": int(time.time() - START_TIME), "db_bytes": db_bytes, "requests_5m": len(recent),
            "errors_5m": sum(1 for r in recent if r["status"] >= 500),
            "avg_ms": round(sum(r["ms"] for r in recent) / len(recent)) if recent else 0,
            "blocked_ips": len(BLOCKED_IPS), "tables": {n: db.query(t).count() for n, t in Base.metadata.tables.items()}}

HIDDEN_COLS = {"hashed_password", "verification_code"}

@app.get("/api/admin/db")
def admin_db_tables(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    return [{"name": n, "rows": db.query(t).count(), "columns": [c.name for c in t.columns if c.name not in HIDDEN_COLS]} for n, t in Base.metadata.tables.items()]

@app.get("/api/admin/db/{table}")
def admin_db_rows(table: str, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    t = Base.metadata.tables.get(table)
    if t is None:
        raise HTTPException(status_code=404, detail="Unknown table")
    q = select(*[c for c in t.columns if c.name not in HIDDEN_COLS]).order_by(t.c.id.desc()).limit(200)
    if table == "records":
        q = q.where(t.c.kind != "key")
    return [dict(r) for r in db.execute(q).mappings().all()]

@app.get("/api/admin/analytics")
def admin_analytics(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    users, tickets, invs = db.query(UserDB).all(), db.query(TicketDB).all(), db.query(InvoiceDB).all()
    emails = {u.id: u.email for u in users}
    rev, per_client, total = {}, Counter(), 0.0
    for i in invs:
        try: amt = float(str(i.amount).replace("$", "").replace(",", ""))
        except ValueError: amt = 0.0
        try: key = datetime.strptime(i.date, "%b %d, %Y").strftime("%Y-%m")
        except ValueError: key = "unknown"
        rev[key] = rev.get(key, 0) + amt; total += amt; per_client[emails.get(i.user_id, "deleted")] += amt
    hours = Counter(r["time"][11:13] + ":00" for r in REQ_LOG if time.time() - r["ts"] < 43200)
    return {"users_total": len(users), "users_verified": sum(1 for u in users if u.is_verified), "tickets_total": len(tickets),
            "revenue_total": total, "invoice_count": len(invs),
            "by_role": [list(x) for x in Counter(u.role for u in users).items()],
            "top_companies": [list(x) for x in Counter(u.company_name for u in users if u.company_name).most_common(8)],
            "tickets_by_category": [list(x) for x in Counter(t.category for t in tickets).items()],
            "tickets_by_status": [list(x) for x in Counter(t.status for t in tickets).items()],
            "revenue_by_month": sorted([list(x) for x in rev.items()]), "top_clients": [list(x) for x in per_client.most_common(10)],
            "requests_by_hour": sorted([list(x) for x in hours.items()])}

@app.get("/api/admin/feed")
def admin_feed(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    ev = [{"t": a.created_at, "kind": "audit", "msg": f"{a.actor} · {a.action} · {a.detail}"}
          for a in db.query(AuditDB).order_by(AuditDB.id.desc()).limit(25).all()]
    ev += [{"t": r["time"], "kind": "error" if r["status"] >= 500 else "req", "msg": f'{r["method"]} {r["path"]} → {r["status"]} ({r["ms"]}ms) {r["ip"]}'}
           for r in list(REQ_LOG) if not r["path"].startswith("/api/admin")][:30]
    return sorted(ev, key=lambda e: e["t"], reverse=True)[:50]

@app.get("/api/announcements")
def public_announcements(db=Depends(get_db)):
    out = []
    for r in db.query(RecordDB).filter(RecordDB.kind == "announcement").order_by(RecordDB.id.desc()).all():
        d = json.loads(r.data or "{}")
        if d.get("status", "Active") == "Active":
            out.append({"title": d.get("title", ""), "message": d.get("message", ""), "level": d.get("level", "info")})
    return out
