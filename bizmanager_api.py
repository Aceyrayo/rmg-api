"""
RMG BizManager API  -  multi-business inventory, sales, invoicing, expenses, team and reports.
Lives next to main.py (same folder). main.py loads it with two lines:
    from bizmanager_api import router as biz_router
    app.include_router(biz_router)
Every business ("workspace") is fully isolated: each request is checked against the caller's role in that workspace.
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, Float, Integer, String, Text, func

from main import Base, UserDB, audit, engine, get_current_user, get_db, now_str, rate_hit, rate_ok, require_admin, send_email

router = APIRouter(prefix="/api/biz", tags=["bizmanager"])

# ------------------------------------------------------------------ tables
class BizWorkspace(Base):
    __tablename__ = "biz_workspaces"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, index=True)
    name = Column(String)
    currency = Column(String, default="USD")
    tax_rate = Column(Float, default=0.0)
    address = Column(String, default="")
    phone = Column(String, default="")
    email = Column(String, default="")
    invoice_prefix = Column(String, default="INV")
    next_number = Column(Integer, default=1)
    plan = Column(String, default="trial")  # trial | active | suspended
    trial_ends = Column(String)
    created_at = Column(String)

class BizMember(Base):
    __tablename__ = "biz_members"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    user_id = Column(Integer, index=True, nullable=True)
    email = Column(String, index=True)
    role = Column(String)
    status = Column(String, default="Invited")  # Invited | Active
    created_at = Column(String)

class BizProduct(Base):
    __tablename__ = "biz_products"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    name = Column(String)
    sku = Column(String, default="")
    category = Column(String, default="")
    unit = Column(String, default="pcs")
    price = Column(Float, default=0.0)
    cost = Column(Float, default=0.0)
    stock = Column(Float, default=0.0)
    low_stock = Column(Float, default=5.0)
    active = Column(Boolean, default=True)
    created_at = Column(String)

class BizCustomer(Base):
    __tablename__ = "biz_customers"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    name = Column(String)
    email = Column(String, default="")
    phone = Column(String, default="")
    address = Column(String, default="")
    notes = Column(String, default="")
    created_at = Column(String)

class BizSale(Base):
    __tablename__ = "biz_sales"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    number = Column(String, index=True)
    kind = Column(String, default="sale")  # sale (receipt) | invoice
    customer_id = Column(Integer, nullable=True)
    customer_name = Column(String, default="")
    items = Column(Text, default="[]")
    subtotal = Column(Float, default=0.0)
    discount = Column(Float, default=0.0)
    tax = Column(Float, default=0.0)
    total = Column(Float, default=0.0)
    paid = Column(Float, default=0.0)
    method = Column(String, default="Cash")
    status = Column(String, default="Paid")  # Paid | Partial | Unpaid | Void
    date = Column(String, index=True)
    due_date = Column(String, nullable=True)
    notes = Column(String, default="")
    created_by = Column(Integer)
    created_at = Column(String)

class BizPayment(Base):
    __tablename__ = "biz_payments"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    sale_id = Column(Integer, index=True)
    amount = Column(Float)
    method = Column(String, default="Cash")
    date = Column(String)
    note = Column(String, default="")
    created_at = Column(String)

class BizExpense(Base):
    __tablename__ = "biz_expenses"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    category = Column(String, default="General")
    vendor = Column(String, default="")
    description = Column(String, default="")
    amount = Column(Float)
    date = Column(String, index=True)
    created_by = Column(Integer)
    created_at = Column(String)

class BizStock(Base):
    __tablename__ = "biz_stock_moves"
    id = Column(Integer, primary_key=True, index=True)
    ws_id = Column(Integer, index=True)
    product_id = Column(Integer, index=True)
    delta = Column(Float)
    reason = Column(String)
    ref = Column(String, default="")
    balance = Column(Float)
    created_at = Column(String)

Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------ helpers
TRIAL_DAYS, MAX_WORKSPACES = 14, 3
PERMS = {
    "Owner": {"view", "sell", "inventory", "finance", "void", "team", "settings"},
    "Manager": {"view", "sell", "inventory", "finance", "void"},
    "Cashier": {"view", "sell"},
    "Accountant": {"view", "finance"},
}

def r2(x) -> float:
    return round(float(x or 0) + 1e-9, 2)

def today_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d")

def ds(s, default=None):
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return default

def is_writable(ws) -> bool:
    if ws.plan == "active":
        return True
    return ws.plan == "trial" and (ws.trial_ends or "") >= today_utc()

def ws_dict(ws, role):
    days = None
    if ws.plan == "trial" and ws.trial_ends:
        days = (datetime.strptime(ws.trial_ends, "%Y-%m-%d").date() - datetime.utcnow().date()).days
    return {
        "id": ws.id, "name": ws.name, "currency": ws.currency, "tax_rate": ws.tax_rate,
        "address": ws.address, "phone": ws.phone, "email": ws.email,
        "invoice_prefix": ws.invoice_prefix, "plan": ws.plan, "trial_ends": ws.trial_ends,
        "days_left": days, "writable": is_writable(ws), "role": role,
        "perms": sorted(PERMS.get(role, set()))
    }

def access(db, ws_id: int, user, perm: str = "view", write: bool = False):
    """Return (workspace, role) or raise. Enforces tenant isolation, role permissions and trial/plan status."""
    ws = db.get(BizWorkspace, ws_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Business not found")
    if getattr(user, "role", None) == "admin":
        role = "Owner"
    else:
        role = "Owner" if ws.owner_id == user.id else None
        if not role:
            m = db.query(BizMember).filter(BizMember.ws_id == ws_id, BizMember.user_id == user.id, BizMember.status == "Active").first()
            role = m.role if m else None
    if not role:
        raise HTTPException(status_code=404, detail="Business not found")
    if perm not in PERMS.get(role, set()):
        raise HTTPException(status_code=403, detail="Your role does not allow this action")
    if write and not is_writable(ws):
        raise HTTPException(status_code=402, detail="Your free trial has ended or this account is inactive. Contact RMG to activate BizManager.")
    return ws, role

def bad(msg: str):
    raise HTTPException(status_code=400, detail=msg)

def clean(s, n=120) -> str:
    return (s or "").strip()[:n]

# ------------------------------------------------------------------ businesses
class WorkspaceIn(BaseModel):
    name: str
    currency: str = "USD"
    tax_rate: float = 0
    address: str = ""
    phone: str = ""
    email: str = ""

class SettingsIn(BaseModel):
    name: Optional[str] = None
    currency: Optional[str] = None
    tax_rate: Optional[float] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    invoice_prefix: Optional[str] = None

@router.get("/workspaces")
def my_workspaces(user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    if getattr(user, "role", None) == "admin":
        out = [ws_dict(w, "Owner") for w in db.query(BizWorkspace).order_by(BizWorkspace.id.desc()).all()]
    else:
        out = [ws_dict(w, "Owner") for w in db.query(BizWorkspace).filter(BizWorkspace.owner_id == user.id).all()]
        seen = {w["id"] for w in out}
        for m in db.query(BizMember).filter(BizMember.user_id == user.id, BizMember.status == "Active").all():
            w = db.get(BizWorkspace, m.ws_id)
            if w and w.id not in seen:
                out.append(ws_dict(w, m.role))
                seen.add(w.id)
    invites = []
    for m in db.query(BizMember).filter(BizMember.status == "Invited", func.lower(BizMember.email) == user.email.lower()).all():
        w = db.get(BizWorkspace, m.ws_id)
        if w:
            invites.append({"id": m.id, "business": w.name, "role": m.role})
    return {"workspaces": out, "invites": invites}

@router.post("/workspaces")
def create_workspace(data: WorkspaceIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    if db.query(BizWorkspace).filter(BizWorkspace.owner_id == user.id).count() >= MAX_WORKSPACES:
        bad(f"You can own up to {MAX_WORKSPACES} businesses.")
    if not clean(data.name):
        bad("Enter your business name.")
    ws = BizWorkspace(
        owner_id=user.id, name=clean(data.name), currency=(data.currency or "USD").upper()[:3],
        tax_rate=max(0, min(data.tax_rate, 100)), address=clean(data.address, 200),
        phone=clean(data.phone, 40), email=clean(data.email, 120),
        trial_ends=(datetime.utcnow() + timedelta(days=TRIAL_DAYS)).strftime("%Y-%m-%d"),
        created_at=now_str()
    )
    db.add(ws); db.commit()
    audit(db, user.username, "BIZ_CREATE", ws.name)
    return ws_dict(ws, "Owner")

@router.patch("/{ws_id}/settings")
def update_settings(ws_id: int, data: SettingsIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, role = access(db, ws_id, user, "settings", write=True)
    d = data.dict(exclude_unset=True)
    if "name" in d and not clean(d["name"]):
        bad("Business name cannot be empty.")
    for k, v in d.items():
        if k == "tax_rate":
            v = max(0, min(float(v or 0), 100))
        elif k == "currency":
            v = (v or "USD").upper()[:3]
        elif k == "invoice_prefix":
            v = clean(v, 8).upper() or "INV"
        elif v is not None:
            v = clean(v, 200)
        setattr(ws, k, v)
    db.commit()
    return ws_dict(ws, role)

@router.post("/invites/{member_id}/accept")
def accept_invite(member_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    m = db.get(BizMember, member_id)
    if not m or m.status != "Invited" or (m.email or "").lower() != user.email.lower():
        raise HTTPException(status_code=404, detail="Invitation not found")
    m.user_id, m.status = user.id, "Active"; db.commit()
    return {"message": "You have joined the business."}

@router.delete("/invites/{member_id}")
def decline_invite(member_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    m = db.get(BizMember, member_id)
    if not m or m.status != "Invited" or (m.email or "").lower() != user.email.lower():
        raise HTTPException(status_code=404, detail="Invitation not found")
    db.delete(m); db.commit()
    return {"message": "Invitation declined."}

# ------------------------------------------------------------------ team
class MemberIn(BaseModel):
    email: str
    role: str = "Cashier"

class RoleIn(BaseModel):
    role: str

@router.get("/{ws_id}/members")
def members_list(ws_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, _ = access(db, ws_id, user, "team")
    owner = db.get(UserDB, ws.owner_id)
    out = [{"id": 0, "email": owner.email if owner else "", "name": f"{owner.first_name} {owner.last_name}" if owner else "Owner", "role": "Owner", "status": "Active"}]
    for m in db.query(BizMember).filter(BizMember.ws_id == ws_id).order_by(BizMember.id).all():
        u = db.get(UserDB, m.user_id) if m.user_id else None
        out.append({"id": m.id, "email": m.email, "name": f"{u.first_name} {u.last_name}" if u else "", "role": m.role, "status": m.status})
    return out

@router.post("/{ws_id}/members")
def member_invite(ws_id: int, data: MemberIn, bg: BackgroundTasks, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, _ = access(db, ws_id, user, "team", write=True)
    em = clean(data.email, 120).lower()
    if "@" not in em or "." not in em.split("@")[-1]:
        bad("Enter a valid email address.")
    if data.role not in ("Manager", "Cashier", "Accountant"):
        bad("Role must be Manager, Cashier or Accountant.")
    if db.query(BizMember).filter(BizMember.ws_id == ws_id, func.lower(BizMember.email) == em).first() or em == user.email.lower():
        bad("That person already has access.")
    if db.query(BizMember).filter(BizMember.ws_id == ws_id).count() >= 50:
        bad("Team limit reached.")
    m = BizMember(ws_id=ws_id, email=em, role=data.role, status="Invited", created_at=now_str())
    db.add(m); db.commit()
    bg.add_task(
        send_email, em, f"You've been invited to {ws.name} on RMG BizManager",
        f"<div style='font-family:sans-serif'><h2>You're invited</h2><p>{user.first_name} {user.last_name} invited you to join <b>{ws.name}</b> as <b>{data.role}</b>.</p>"
        f"<p>Sign in (or create an account with this email) at your RMG site and open <b>BizManager</b> to accept.</p></div>"
    )
    audit(db, user.username, "BIZ_INVITE", f"{em} as {data.role}")
    return {"id": m.id, "email": em, "role": data.role, "status": "Invited"}

@router.patch("/{ws_id}/members/{member_id}")
def member_role(ws_id: int, member_id: int, data: RoleIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "team", write=True)
    m = db.get(BizMember, member_id)
    if not m or m.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Member not found")
    if data.role not in ("Manager", "Cashier", "Accountant"):
        bad("Invalid role.")
    m.role = data.role; db.commit()
    return {"message": "Role updated"}

@router.delete("/{ws_id}/members/{member_id}")
def member_remove(ws_id: int, member_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "team")
    m = db.get(BizMember, member_id)
    if not m or m.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Member not found")
    db.delete(m); db.commit()
    return {"message": "Removed"}

# ------------------------------------------------------------------ products & stock
class ProductIn(BaseModel):
    name: str
    sku: str = ""
    category: str = ""
    unit: str = "pcs"
    price: float = 0
    cost: float = 0
    stock: float = 0
    low_stock: float = 5
    active: bool = True

class ProductPatch(BaseModel):
    name: Optional[str] = None
    sku: Optional[str] = None
    category: Optional[str] = None
    unit: Optional[str] = None
    price: Optional[float] = None
    cost: Optional[float] = None
    low_stock: Optional[float] = None
    active: Optional[bool] = None

class AdjustIn(BaseModel):
    delta: float
    reason: str = "Adjustment"
    cost: Optional[float] = None

class BulkIn(BaseModel):
    items: List[ProductIn]

def prod_out(p):
    return {
        "id": p.id, "name": p.name, "sku": p.sku, "category": p.category, "unit": p.unit,
        "price": p.price, "cost": p.cost, "stock": p.stock, "low_stock": p.low_stock,
        "active": p.active, "low": bool(p.active and p.stock <= p.low_stock),
        "margin": r2((p.price - p.cost) / p.price * 100) if p.price else 0
    }

def check_product(d):
    if not clean(d.name):
        bad("Product name is required.")
    if d.price < 0 or d.cost < 0 or d.stock < 0 or d.low_stock < 0:
        bad("Prices and quantities cannot be negative.")

@router.get("/{ws_id}/products")
def products_list(ws_id: int, q: str = "", low: bool = False, archived: bool = False, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "view")
    rows = db.query(BizProduct).filter(BizProduct.ws_id == ws_id).order_by(BizProduct.name).all()
    q = q.strip().lower()
    out = [prod_out(p) for p in rows if (p.active != archived) and (not q or q in (p.name or "").lower() or q in (p.sku or "").lower() or q in (p.category or "").lower())]
    return [p for p in out if p["low"]] if low else out

@router.post("/{ws_id}/products")
def product_create(ws_id: int, data: ProductIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "inventory", write=True)
    check_product(data)
    sku = clean(data.sku, 40)
    if sku and db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.sku == sku).first():
        bad("A product with that SKU already exists.")
    p = BizProduct(
        ws_id=ws_id, name=clean(data.name), sku=sku, category=clean(data.category, 60),
        unit=clean(data.unit, 12) or "pcs", price=r2(data.price), cost=r2(data.cost),
        stock=data.stock, low_stock=data.low_stock, active=True, created_at=now_str()
    )
    db.add(p); db.flush()
    if data.stock:
        db.add(BizStock(ws_id=ws_id, product_id=p.id, delta=data.stock, reason="Opening stock", ref="", balance=data.stock, created_at=now_str()))
    db.commit()
    return prod_out(p)

@router.post("/{ws_id}/products/bulk")
def product_bulk(ws_id: int, data: BulkIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "inventory", write=True)
    if len(data.items) > 500:
        bad("Import up to 500 products at a time.")
    have = {p.sku for p in db.query(BizProduct).filter(BizProduct.ws_id == ws_id).all() if p.sku}
    made = skipped = 0
    for d in data.items:
        sku = clean(d.sku, 40)
        if not clean(d.name) or min(d.price, d.cost, d.stock, d.low_stock) < 0 or (sku and sku in have):
            skipped += 1; continue
        p = BizProduct(
            ws_id=ws_id, name=clean(d.name), sku=sku, category=clean(d.category, 60),
            unit=clean(d.unit, 12) or "pcs", price=r2(d.price), cost=r2(d.cost),
            stock=d.stock, low_stock=d.low_stock, active=True, created_at=now_str()
        )
        db.add(p); db.flush()
        if d.stock:
            db.add(BizStock(ws_id=ws_id, product_id=p.id, delta=d.stock, reason="Opening stock", ref="import", balance=d.stock, created_at=now_str()))
        if sku:
            have.add(sku)
        made += 1
    db.commit()
    return {"created": made, "skipped": skipped}

def get_product(db, ws_id, pid):
    p = db.get(BizProduct, pid)
    if not p or p.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Product not found")
    return p

@router.patch("/{ws_id}/products/{pid}")
def product_update(ws_id: int, pid: int, data: ProductPatch, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "inventory", write=True)
    p = get_product(db, ws_id, pid)
    d = data.dict(exclude_unset=True)
    if "sku" in d:
        d["sku"] = clean(d["sku"], 40)
        if d["sku"] and db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.sku == d["sku"], BizProduct.id != pid).first():
            bad("A product with that SKU already exists.")
    if "name" in d and not clean(d["name"]):
        bad("Product name is required.")
    for k in ("price", "cost", "low_stock"):
        if k in d and (d[k] is None or d[k] < 0):
            bad("Prices and quantities cannot be negative.")
    for k, v in d.items():
        setattr(p, k, clean(v, 120) if isinstance(v, str) else v)
    db.commit()
    return prod_out(p)

@router.delete("/{ws_id}/products/{pid}")
def product_archive(ws_id: int, pid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "inventory", write=True)
    p = get_product(db, ws_id, pid)
    p.active = False; db.commit()
    return {"message": "Product archived"}

@router.post("/{ws_id}/products/{pid}/adjust")
def product_adjust(ws_id: int, pid: int, data: AdjustIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "inventory", write=True)
    p = get_product(db, ws_id, pid)
    if data.delta == 0:
        bad("Enter a quantity to add or remove.")
    new = p.stock + data.delta
    if new < -1e-9:
        bad(f"Cannot remove more than the {p.stock:g} in stock.")
    if data.cost is not None and data.delta > 0 and data.cost >= 0:
        p.cost = r2((p.stock * p.cost + data.delta * data.cost) / new) if new > 0 else r2(data.cost)
    p.stock = max(new, 0)
    db.add(BizStock(ws_id=ws_id, product_id=p.id, delta=data.delta, reason=clean(data.reason, 60) or "Adjustment", ref=user.username, balance=p.stock, created_at=now_str()))
    db.commit()
    return prod_out(p)

@router.get("/{ws_id}/products/{pid}/moves")
def product_moves(ws_id: int, pid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "view")
    get_product(db, ws_id, pid)
    rows = db.query(BizStock).filter(BizStock.ws_id == ws_id, BizStock.product_id == pid).order_by(BizStock.id.desc()).limit(100).all()
    return [{"id": m.id, "delta": m.delta, "reason": m.reason, "ref": m.ref, "balance": m.balance, "at": m.created_at} for m in rows]

# ------------------------------------------------------------------ customers
class CustomerIn(BaseModel):
    name: str
    email: str = ""
    phone: str = ""
    address: str = ""
    notes: str = ""

def sale_totals(db, ws_id):
    stats = defaultdict(lambda: {"billed": 0.0, "balance": 0.0, "count": 0})
    for s in db.query(BizSale).filter(BizSale.ws_id == ws_id, BizSale.status != "Void", BizSale.customer_id.isnot(None)).all():
        c = stats[s.customer_id]
        c["billed"] += s.total; c["balance"] += max(s.total - s.paid, 0); c["count"] += 1
    return stats

def cust_out(c, st=None):
    st = st or {"billed": 0, "balance": 0, "count": 0}
    return {
        "id": c.id, "name": c.name, "email": c.email, "phone": c.phone, "address": c.address, "notes": c.notes,
        "billed": r2(st["billed"]), "balance": r2(st["balance"]), "documents": st["count"]
    }

@router.get("/{ws_id}/customers")
def customers_list(ws_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "view")
    stats = sale_totals(db, ws_id)
    return [cust_out(c, stats.get(c.id)) for c in db.query(BizCustomer).filter(BizCustomer.ws_id == ws_id).order_by(BizCustomer.name).all()]

@router.post("/{ws_id}/customers")
def customer_create(ws_id: int, data: CustomerIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "sell", write=True)
    if not clean(data.name):
        bad("Customer name is required.")
    c = BizCustomer(ws_id=ws_id, name=clean(data.name), email=clean(data.email), phone=clean(data.phone, 40), address=clean(data.address, 200), notes=clean(data.notes, 500), created_at=now_str())
    db.add(c); db.commit()
    return cust_out(c)

def get_customer(db, ws_id, cid):
    c = db.get(BizCustomer, cid)
    if not c or c.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Customer not found")
    return c

@router.patch("/{ws_id}/customers/{cid}")
def customer_update(ws_id: int, cid: int, data: CustomerIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "sell", write=True)
    c = get_customer(db, ws_id, cid)
    if not clean(data.name):
        bad("Customer name is required.")
    c.name, c.email, c.phone = clean(data.name), clean(data.email), clean(data.phone, 40)
    c.address, c.notes = clean(data.address, 200), clean(data.notes, 500)
    db.commit()
    return cust_out(c)

@router.delete("/{ws_id}/customers/{cid}")
def customer_delete(ws_id: int, cid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "void", write=True)
    c = get_customer(db, ws_id, cid)
    if db.query(BizSale).filter(BizSale.ws_id == ws_id, BizSale.customer_id == cid).first():
        bad("This customer has sales history and cannot be deleted.")
    db.delete(c); db.commit()
    return {"message": "Customer deleted"}

# ------------------------------------------------------------------ sales, invoices, payments
class SaleItemIn(BaseModel):
    product_id: Optional[int] = None
    name: str = ""
    qty: float = 1
    price: Optional[float] = None

class SaleIn(BaseModel):
    kind: str = "sale"
    customer_id: Optional[int] = None
    customer_name: str = ""
    items: List[SaleItemIn]
    discount: float = 0
    tax_rate: Optional[float] = None
    paid: Optional[float] = None
    method: str = "Cash"
    date: Optional[str] = None
    due_date: Optional[str] = None
    notes: str = ""

class PaymentIn(BaseModel):
    amount: float
    method: str = "Cash"
    date: Optional[str] = None
    note: str = ""

class EmailIn(BaseModel):
    to: str = ""

def sale_status(total, paid):
    return "Paid" if paid >= total - 0.005 else ("Partial" if paid > 0 else "Unpaid")

def sale_out(s, detail=False, payments=None, today=None):
    today = today or today_utc()
    out = {
        "id": s.id, "number": s.number, "kind": s.kind, "customer_id": s.customer_id,
        "customer_name": s.customer_name, "subtotal": s.subtotal, "discount": s.discount,
        "tax": s.tax, "total": s.total, "paid": s.paid, "balance": r2(max(s.total - s.paid, 0)),
        "method": s.method, "status": s.status, "date": s.date, "due_date": s.due_date,
        "notes": s.notes, "overdue": bool(s.status in ("Unpaid", "Partial") and s.due_date and s.due_date < today)
    }
    if detail:
        out["items"] = json.loads(s.items or "[]")
        out["payments"] = [{"id": p.id, "amount": p.amount, "method": p.method, "date": p.date, "note": p.note} for p in (payments or [])]
    return out

@router.post("/{ws_id}/sales")
def sale_create(ws_id: int, data: SaleIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, _ = access(db, ws_id, user, "sell", write=True)
    if data.kind not in ("sale", "invoice"):
        bad("Kind must be sale or invoice.")
    if not data.items or len(data.items) > 100:
        bad("Add between 1 and 100 line items.")
    pids = {i.product_id for i in data.items if i.product_id}
    prods = {p.id: p for p in db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.id.in_(pids)).all()} if pids else {}
    lines, need = [], defaultdict(float)
    for it in data.items:
        if it.qty <= 0:
            bad("Quantities must be greater than zero.")
        if it.product_id:
            p = prods.get(it.product_id)
            if not p or not p.active:
                bad("A selected product is no longer available.")
            price = r2(it.price if it.price is not None else p.price)
            if price < 0:
                bad("Prices cannot be negative.")
            need[p.id] += it.qty
            lines.append({"product_id": p.id, "name": p.name, "sku": p.sku, "qty": it.qty, "price": price, "cost": r2(p.cost), "total": r2(it.qty * price)})
        else:
            if not clean(it.name) or it.price is None or it.price < 0:
                bad("Custom items need a name and a price.")
            lines.append({"product_id": None, "name": clean(it.name), "sku": "", "qty": it.qty, "price": r2(it.price), "cost": 0, "total": r2(it.qty * it.price)})
    for pid, q in need.items():
        if prods[pid].stock < q - 1e-9:
            bad(f"Not enough stock for {prods[pid].name} (available {prods[pid].stock:g}).")
    subtotal = r2(sum(l["total"] for l in lines))
    discount = r2(min(max(data.discount, 0), subtotal))
    rate = ws.tax_rate if data.tax_rate is None else max(0, min(data.tax_rate, 100))
    tax = r2((subtotal - discount) * rate / 100)
    total = r2(subtotal - discount + tax)
    cname = clean(data.customer_name)
    if data.customer_id:
        cname = get_customer(db, ws_id, data.customer_id).name
    if data.kind == "invoice" and not cname:
        bad("Invoices need a customer.")
    paid = total if (data.kind == "sale" and data.paid is None) else r2(min(max(data.paid or 0, 0), total))
    day = ds(data.date, today_utc())
    s = BizSale(
        ws_id=ws_id, number=f"{'RCT' if data.kind == 'sale' else (ws.invoice_prefix or 'INV')}-{ws.next_number:05d}",
        kind=data.kind, customer_id=data.customer_id, customer_name=cname, items=json.dumps(lines),
        subtotal=subtotal, discount=discount, tax=tax, total=total, paid=paid,
        method=clean(data.method, 30) or "Cash", status=sale_status(total, paid), date=day,
        due_date=ds(data.due_date) if data.kind == "invoice" else None, notes=clean(data.notes, 500),
        created_by=user.id, created_at=now_str()
    )
    ws.next_number += 1
    db.add(s); db.flush()
    for pid, q in need.items():
        p = prods[pid]; p.stock = max(p.stock - q, 0)
        db.add(BizStock(ws_id=ws_id, product_id=pid, delta=-q, reason="Sale", ref=s.number, balance=p.stock, created_at=now_str()))
    if paid > 0:
        db.add(BizPayment(ws_id=ws_id, sale_id=s.id, amount=paid, method=s.method, date=day, note="Initial payment", created_at=now_str()))
    db.commit()
    audit(db, user.username, "BIZ_SALE", f"{s.number} {total}")
    return sale_out(s, True, db.query(BizPayment).filter(BizPayment.sale_id == s.id).all())

@router.get("/{ws_id}/sales")
def sales_list(
    ws_id: int, kind: str = "", status: str = "", q: str = "", date_from: str = "",
    date_to: str = "", customer_id: int = 0, user: UserDB = Depends(get_current_user), db=Depends(get_db)
):
    access(db, ws_id, user, "view")
    qry = db.query(BizSale).filter(BizSale.ws_id == ws_id)
    if kind in ("sale", "invoice"): qry = qry.filter(BizSale.kind == kind)
    if status in ("Paid", "Partial", "Unpaid", "Void"): qry = qry.filter(BizSale.status == status)
    if ds(date_from): qry = qry.filter(BizSale.date >= date_from)
    if ds(date_to): qry = qry.filter(BizSale.date <= date_to)
    if customer_id: qry = qry.filter(BizSale.customer_id == customer_id)
    q = q.strip().lower()
    rows = [s for s in qry.order_by(BizSale.id.desc()).limit(1000).all() if not q or q in (s.number or "").lower() or q in (s.customer_name or "").lower()]
    return [sale_out(s) for s in rows[:500]]

def get_sale(db, ws_id, sid):
    s = db.get(BizSale, sid)
    if not s or s.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Document not found")
    return s

@router.get("/{ws_id}/sales/{sid}")
def sale_get(ws_id: int, sid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "view")
    s = get_sale(db, ws_id, sid)
    return sale_out(s, True, db.query(BizPayment).filter(BizPayment.sale_id == sid).order_by(BizPayment.id).all())

@router.post("/{ws_id}/sales/{sid}/payments")
def sale_pay(ws_id: int, sid: int, data: PaymentIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "sell", write=True)
    s = get_sale(db, ws_id, sid)
    if s.status == "Void":
        bad("This document is void.")
    amt, due = r2(data.amount), r2(s.total - s.paid)
    if amt <= 0:
        bad("Enter a payment amount.")
    if amt > due + 0.005:
        bad(f"The balance due is only {due:.2f}.")
    db.add(BizPayment(ws_id=ws_id, sale_id=sid, amount=amt, method=clean(data.method, 30) or "Cash", date=ds(data.date, today_utc()), note=clean(data.note, 200), created_at=now_str()))
    s.paid = r2(s.paid + amt); s.status = sale_status(s.total, s.paid)
    db.commit()
    audit(db, user.username, "BIZ_PAYMENT", f"{s.number} {amt}")
    return sale_out(s, True, db.query(BizPayment).filter(BizPayment.sale_id == sid).order_by(BizPayment.id).all())

@router.post("/{ws_id}/sales/{sid}/void")
def sale_void(ws_id: int, sid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "void", write=True)
    s = get_sale(db, ws_id, sid)
    if s.status == "Void":
        bad("Already void.")
    for l in json.loads(s.items or "[]"):
        p = db.get(BizProduct, l.get("product_id")) if l.get("product_id") else None
        if p and p.ws_id == ws_id:
            p.stock += l["qty"]
            db.add(BizStock(ws_id=ws_id, product_id=p.id, delta=l["qty"], reason="Void", ref=s.number, balance=p.stock, created_at=now_str()))
    s.status = "Void"; db.commit()
    audit(db, user.username, "BIZ_VOID", s.number)
    return sale_out(s, True, [])

@router.post("/{ws_id}/sales/{sid}/email")
def sale_email(ws_id: int, sid: int, data: EmailIn, bg: BackgroundTasks, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, _ = access(db, ws_id, user, "sell")
    s = get_sale(db, ws_id, sid)
    to = clean(data.to, 120)
    if not to and s.customer_id:
        to = get_customer(db, ws_id, s.customer_id).email
    if "@" not in to:
        bad("Add a customer email address first.")
    if not rate_ok(f"bizmail:{ws_id}", 30, 3600):
        bad("Email limit reached for this hour. Try again later.")
    rate_hit(f"bizmail:{ws_id}")
    rows = "".join(f"<tr><td style='padding:6px 8px;border-bottom:1px solid #e2e8f0'>{l['name']}</td><td style='padding:6px 8px;border-bottom:1px solid #e2e8f0;text-align:right'>{l['qty']:g}</td><td style='padding:6px 8px;border-bottom:1px solid #e2e8f0;text-align:right'>{l['total']:.2f}</td></tr>" for l in json.loads(s.items or "[]"))
    html = (
        f"<div style='font-family:sans-serif;max-width:620px;margin:auto'><h2>{ws.name}</h2><p>{'Invoice' if s.kind == 'invoice' else 'Receipt'} <b>{s.number}</b> · {s.date}</p>"
        f"<table style='width:100%;border-collapse:collapse'><tr><th align=left>Item</th><th align=right>Qty</th><th align=right>Amount</th></tr>{rows}</table>"
        f"<p style='text-align:right'>Total <b>{ws.currency} {s.total:.2f}</b><br>Paid {s.paid:.2f} · Balance <b>{max(s.total - s.paid, 0):.2f}</b></p>"
        f"{'<p>Due date: ' + s.due_date + '</p>' if s.due_date else ''}<p style='color:#64748b'>{ws.phone} {ws.email}</p></div>"
    )
    bg.add_task(send_email, to, f"{'Invoice' if s.kind == 'invoice' else 'Receipt'} {s.number} from {ws.name}", html)
    return {"message": f"Sent to {to}"}

# ------------------------------------------------------------------ expenses
class ExpenseIn(BaseModel):
    category: str = "General"
    vendor: str = ""
    description: str = ""
    amount: float
    date: Optional[str] = None

def exp_out(e):
    return {"id": e.id, "category": e.category, "vendor": e.vendor, "description": e.description, "amount": e.amount, "date": e.date}

@router.get("/{ws_id}/expenses")
def expenses_list(ws_id: int, date_from: str = "", date_to: str = "", user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance")
    qry = db.query(BizExpense).filter(BizExpense.ws_id == ws_id)
    if ds(date_from): qry = qry.filter(BizExpense.date >= date_from)
    if ds(date_to): qry = qry.filter(BizExpense.date <= date_to)
    return [exp_out(e) for e in qry.order_by(BizExpense.date.desc(), BizExpense.id.desc()).limit(1000).all()]

@router.post("/{ws_id}/expenses")
def expense_create(ws_id: int, data: ExpenseIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance", write=True)
    if data.amount <= 0:
        bad("Amount must be greater than zero.")
    e = BizExpense(ws_id=ws_id, category=clean(data.category, 40) or "General", vendor=clean(data.vendor, 80), description=clean(data.description, 200), amount=r2(data.amount), date=ds(data.date, today_utc()), created_by=user.id, created_at=now_str())
    db.add(e); db.commit()
    return exp_out(e)

@router.patch("/{ws_id}/expenses/{eid}")
def expense_update(ws_id: int, eid: int, data: ExpenseIn, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance", write=True)
    e = db.get(BizExpense, eid)
    if not e or e.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Expense not found")
    if data.amount <= 0:
        bad("Amount must be greater than zero.")
    e.category, e.vendor, e.description = clean(data.category, 40) or "General", clean(data.vendor, 80), clean(data.description, 200)
    e.amount, e.date = r2(data.amount), ds(data.date, e.date)
    db.commit()
    return exp_out(e)

@router.delete("/{ws_id}/expenses/{eid}")
def expense_delete(ws_id: int, eid: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance", write=True)
    e = db.get(BizExpense, eid)
    if not e or e.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Expense not found")
    db.delete(e); db.commit()
    return {"message": "Deleted"}

# ------------------------------------------------------------------ dashboard & reports
def day_range(start, end):
    d0, d1 = datetime.strptime(start, "%Y-%m-%d"), datetime.strptime(end, "%Y-%m-%d")
    return [(d0 + timedelta(days=i)).strftime("%Y-%m-%d") for i in range((d1 - d0).days + 1)]

def profit_view(sales, expenses):
    revenue = sum(s.total - s.tax for s in sales)
    cogs = sum(l.get("qty", 0) * l.get("cost", 0) for s in sales for l in json.loads(s.items or "[]"))
    spend = sum(e.amount for e in expenses)
    return {
        "revenue": r2(revenue), "tax": r2(sum(s.tax for s in sales)), "cogs": r2(cogs),
        "gross": r2(revenue - cogs), "expenses": r2(spend), "net": r2(revenue - cogs - spend),
        "count": len(sales)
    }

def top_products(sales, n=8):
    agg = defaultdict(lambda: {"qty": 0.0, "revenue": 0.0, "profit": 0.0})
    for s in sales:
        for l in json.loads(s.items or "[]"):
            a = agg[l["name"]]
            a["qty"] += l["qty"]; a["revenue"] += l["total"]; a["profit"] += l["total"] - l["qty"] * l.get("cost", 0)
    top = sorted(agg.items(), key=lambda kv: kv[1]["revenue"], reverse=True)[:n]
    return [{"name": k, "qty": r2(v["qty"]), "revenue": r2(v["revenue"]), "profit": r2(v["profit"])} for k, v in top]

@router.get("/{ws_id}/dashboard")
def dashboard(ws_id: int, today: str = "", user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    ws, role = access(db, ws_id, user, "view")
    finance = "finance" in PERMS[role]
    today = ds(today, today_utc()); month = today[:8] + "01"; since = (datetime.strptime(today, "%Y-%m-%d") - timedelta(days=13)).strftime("%Y-%m-%d")
    live = [s for s in db.query(BizSale).filter(BizSale.ws_id == ws_id, BizSale.status != "Void").all()]
    today_sales = [s for s in live if s.date == today]
    month_sales = [s for s in live if s.date >= month]
    per_day = defaultdict(float)
    for s in live:
        if s.date >= since:
            per_day[s.date] += s.total - s.tax
    owing = [s for s in live if s.total - s.paid > 0.005]
    low = [prod_out(p) for p in db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.active == True).all() if p.stock <= p.low_stock]  # noqa: E712
    out = {
        "today": {"revenue": r2(sum(s.total - s.tax for s in today_sales)), "count": len(today_sales)},
        "month": {"revenue": r2(sum(s.total - s.tax for s in month_sales)), "count": len(month_sales)},
        "outstanding": {"amount": r2(sum(s.total - s.paid for s in owing)), "count": len(owing), "overdue": sum(1 for s in owing if s.due_date and s.due_date < today)},
        "low_stock": sorted(low, key=lambda p: p["stock"])[:8], "low_stock_count": len(low),
        "series": [[d, r2(per_day.get(d, 0))] for d in day_range(since, today)],
        "top_products": top_products(month_sales, 5),
        "recent": [sale_out(s, today=today) for s in sorted(live, key=lambda x: x.id, reverse=True)[:6]],
        "finance": finance
    }
    if finance:
        exp = db.query(BizExpense).filter(BizExpense.ws_id == ws_id, BizExpense.date >= month).all()
        cat = defaultdict(float)
        for e in exp:
            cat[e.category] += e.amount
        out["month"].update(profit_view(month_sales, exp))
        out["expenses_by_category"] = sorted([[k, r2(v)] for k, v in cat.items()], key=lambda x: -x[1])
        out["stock_value"] = r2(sum(p.stock * p.cost for p in db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.active == True).all()))  # noqa: E712
    return out

@router.get("/{ws_id}/reports/summary")
def report_summary(ws_id: int, date_from: str = "", date_to: str = "", user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance")
    end = ds(date_to, today_utc()); start = ds(date_from, end[:8] + "01")
    if start > end or (datetime.strptime(end, "%Y-%m-%d") - datetime.strptime(start, "%Y-%m-%d")).days > 800:
        bad("Choose a valid date range (up to about two years).")
    sales = db.query(BizSale).filter(BizSale.ws_id == ws_id, BizSale.status != "Void", BizSale.date >= start, BizSale.date <= end).all()
    exps = db.query(BizExpense).filter(BizExpense.ws_id == ws_id, BizExpense.date >= start, BizExpense.date <= end).all()
    daily = {d: {"revenue": 0.0, "cogs": 0.0, "expenses": 0.0} for d in day_range(start, end)}
    for s in sales:
        daily[s.date]["revenue"] += s.total - s.tax
        daily[s.date]["cogs"] += sum(l.get("qty", 0) * l.get("cost", 0) for l in json.loads(s.items or "[]"))
    for e in exps:
        daily[e.date]["expenses"] += e.amount
    cat, cust = defaultdict(float), defaultdict(float)
    for e in exps:
        cat[e.category] += e.amount
    for s in sales:
        cust[s.customer_name or "Walk-in"] += s.total - s.tax
    pays = defaultdict(float)
    for p in db.query(BizPayment).filter(BizPayment.ws_id == ws_id, BizPayment.date >= start, BizPayment.date <= end).all():
        pays[p.method] += p.amount
    return {
        "from": start, "to": end, "totals": profit_view(sales, exps),
        "daily": [[d, r2(v["revenue"]), r2(v["cogs"]), r2(v["expenses"])] for d, v in daily.items()],
        "expenses_by_category": sorted([[k, r2(v)] for k, v in cat.items()], key=lambda x: -x[1]),
        "top_products": top_products(sales, 10),
        "top_customers": sorted([[k, r2(v)] for k, v in cust.items()], key=lambda x: -x[1])[:10],
        "payments_by_method": sorted([[k, r2(v)] for k, v in pays.items()], key=lambda x: -x[1])
    }

@router.get("/{ws_id}/reports/receivables")
def report_receivables(ws_id: int, today: str = "", user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance")
    today = ds(today, today_utc()); t = datetime.strptime(today, "%Y-%m-%d")
    buckets = {"Not yet due": 0.0, "1-30 days": 0.0, "31-60 days": 0.0, "61-90 days": 0.0, "90+ days": 0.0}
    rows = []
    for s in db.query(BizSale).filter(BizSale.ws_id == ws_id, BizSale.status.in_(["Unpaid", "Partial"])).order_by(BizSale.date).all():
        bal = r2(s.total - s.paid)
        if bal <= 0:
            continue
        due = s.due_date or s.date
        late = (t - datetime.strptime(due, "%Y-%m-%d")).days
        key = "Not yet due" if late <= 0 else "1-30 days" if late <= 30 else "31-60 days" if late <= 60 else "61-90 days" if late <= 90 else "90+ days"
        buckets[key] += bal
        rows.append({"number": s.number, "customer": s.customer_name or "Walk-in", "date": s.date, "due_date": due, "total": s.total, "balance": bal, "days_late": max(late, 0), "bucket": key})
    return {"buckets": [[k, r2(v)] for k, v in buckets.items()], "total": r2(sum(buckets.values())), "rows": rows}

@router.get("/{ws_id}/reports/inventory")
def report_inventory(ws_id: int, user: UserDB = Depends(get_current_user), db=Depends(get_db)):
    access(db, ws_id, user, "finance")
    rows = [
        {
            "name": p.name, "sku": p.sku, "category": p.category, "stock": p.stock,
            "cost": p.cost, "price": p.price, "cost_value": r2(p.stock * p.cost),
            "retail_value": r2(p.stock * p.price), "low": bool(p.stock <= p.low_stock)
        }
        for p in db.query(BizProduct).filter(BizProduct.ws_id == ws_id, BizProduct.active == True).order_by(BizProduct.name).all()  # noqa: E712
    ]
    return {"rows": rows, "cost_value": r2(sum(r["cost_value"] for r in rows)), "retail_value": r2(sum(r["retail_value"] for r in rows)), "low_count": sum(1 for r in rows if r["low"])}

# ------------------------------------------------------------------ RMG admin: manage client businesses
class AdminWorkspacePatch(BaseModel):
    plan: Optional[str] = None
    extend_days: int = 0
    trial_ends: Optional[str] = None
    currency: Optional[str] = None
    tax_rate: Optional[float] = None

class AdminMemberIn(BaseModel):
    email: str
    role: str = "Cashier"
    activate_if_registered: bool = True

class AdminMemberPatch(BaseModel):
    role: Optional[str] = None
    status: Optional[str] = None

@router.get("/admin/workspaces")
def admin_workspaces(admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    out = []
    for w in db.query(BizWorkspace).order_by(BizWorkspace.id.desc()).all():
        o = db.get(UserDB, w.owner_id)
        out.append({
            "id": w.id, "name": w.name, "owner": o.email if o else "deleted",
            "plan": w.plan, "trial_ends": w.trial_ends, "created_at": w.created_at,
            "products": db.query(BizProduct).filter(BizProduct.ws_id == w.id).count(),
            "documents": db.query(BizSale).filter(BizSale.ws_id == w.id).count(),
            "members": db.query(BizMember).filter(BizMember.ws_id == w.id).count() + 1
        })
    return out

@router.patch("/admin/workspaces/{ws_id}")
def admin_workspace_update(ws_id: int, data: AdminWorkspacePatch, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    w = db.get(BizWorkspace, ws_id)
    if not w:
        raise HTTPException(status_code=404, detail="Business not found")
    if data.plan is not None:
        if data.plan not in ("trial", "active", "suspended"):
            bad("Plan must be trial, active or suspended.")
        w.plan = data.plan
    if data.trial_ends:
        parsed_end = ds(data.trial_ends)
        if not parsed_end:
            bad("Invalid trial_ends date (use YYYY-MM-DD).")
        w.trial_ends = parsed_end
    elif data.extend_days:
        base = max(w.trial_ends or today_utc(), today_utc())
        clamped = max(min(data.extend_days, 365), -365)
        w.trial_ends = (datetime.strptime(base, "%Y-%m-%d") + timedelta(days=clamped)).strftime("%Y-%m-%d")
    if data.currency is not None:
        w.currency = (data.currency or "USD").upper()[:3]
    if data.tax_rate is not None:
        w.tax_rate = max(0.0, min(float(data.tax_rate), 100.0))
    db.commit()
    audit(db, admin.username, "BIZ_PLAN", f"#{ws_id} plan={w.plan} trial_ends={w.trial_ends}")
    return {"message": "Updated", "plan": w.plan, "trial_ends": w.trial_ends, "currency": w.currency, "tax_rate": w.tax_rate}

@router.get("/admin/workspaces/{ws_id}/members")
def admin_workspace_members(ws_id: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    w = db.get(BizWorkspace, ws_id)
    if not w:
        raise HTTPException(status_code=404, detail="Business not found")
    owner = db.get(UserDB, w.owner_id)
    rows = [{
        "id": 0,
        "email": owner.email if owner else "",
        "name": f"{owner.first_name or ''} {owner.last_name or ''}".strip() or "Owner",
        "role": "Owner",
        "status": "Active",
    }]
    for m in db.query(BizMember).filter(BizMember.ws_id == ws_id).order_by(BizMember.id).all():
        u = db.get(UserDB, m.user_id) if m.user_id else None
        rows.append({
            "id": m.id,
            "email": m.email,
            "name": f"{u.first_name or ''} {u.last_name or ''}".strip() if u else "",
            "role": m.role,
            "status": m.status,
        })
    return rows

@router.post("/admin/workspaces/{ws_id}/members")
def admin_workspace_member_add(ws_id: int, data: AdminMemberIn, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    w = db.get(BizWorkspace, ws_id)
    if not w:
        raise HTTPException(status_code=404, detail="Business not found")
    em = clean(data.email, 120).lower()
    if "@" not in em or "." not in em.split("@")[-1]:
        bad("Enter a valid email address.")
    if data.role not in ("Manager", "Cashier", "Accountant"):
        bad("Role must be Manager, Cashier or Accountant.")
    owner = db.get(UserDB, w.owner_id)
    if (owner and owner.email.lower() == em) or db.query(BizMember).filter(BizMember.ws_id == ws_id, func.lower(BizMember.email) == em).first():
        bad("That person already belongs to this business.")

    existing_user = db.query(UserDB).filter(func.lower(UserDB.email) == em).first()
    is_active = bool(existing_user and data.activate_if_registered)
    m = BizMember(
        ws_id=ws_id,
        user_id=existing_user.id if is_active else None,
        email=em,
        role=data.role,
        status="Active" if is_active else "Invited",
        created_at=now_str(),
    )
    db.add(m)
    db.commit()
    audit(db, admin.username, "ADMIN_BIZ_MEMBER_ADD", f"#{ws_id} {em} ({data.role}, {m.status})")
    return {"id": m.id, "email": m.email, "role": m.role, "status": m.status}

@router.patch("/admin/workspaces/{ws_id}/members/{member_id}")
def admin_workspace_member_update(ws_id: int, member_id: int, data: AdminMemberPatch, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    m = db.get(BizMember, member_id)
    if not m or m.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Member not found")
    if data.role is not None:
        if data.role not in ("Manager", "Cashier", "Accountant"):
            bad("Role must be Manager, Cashier or Accountant.")
        m.role = data.role
    if data.status is not None:
        if data.status not in ("Invited", "Active"):
            bad("Status must be Invited or Active.")
        if data.status == "Active" and not m.user_id:
            u = db.query(UserDB).filter(func.lower(UserDB.email) == (m.email or "").lower()).first()
            if not u:
                bad("Cannot activate until a user registers with this email.")
            m.user_id = u.id
        m.status = data.status
    db.commit()
    audit(db, admin.username, "ADMIN_BIZ_MEMBER_UPDATE", f"#{ws_id} member#{member_id} role={m.role} status={m.status}")
    return {"message": "Member updated"}

@router.delete("/admin/workspaces/{ws_id}/members/{member_id}")
def admin_workspace_member_remove(ws_id: int, member_id: int, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    m = db.get(BizMember, member_id)
    if not m or m.ws_id != ws_id:
        raise HTTPException(status_code=404, detail="Member not found")
    em = m.email
    db.delete(m)
    db.commit()
    audit(db, admin.username, "ADMIN_BIZ_MEMBER_REMOVE", f"#{ws_id} {em}")
    return {"message": "Member removed"}

@router.get("/admin/workspaces/{ws_id}/ledger")
def admin_workspace_ledger(ws_id: int, limit: int = 100, admin: UserDB = Depends(require_admin), db=Depends(get_db)):
    w = db.get(BizWorkspace, ws_id)
    if not w:
        raise HTTPException(status_code=404, detail="Business not found")
    cap = max(1, min(limit, 500))
    sales = db.query(BizSale).filter(BizSale.ws_id == ws_id).order_by(BizSale.id.desc()).limit(cap).all()
    expenses = db.query(BizExpense).filter(BizExpense.ws_id == ws_id).order_by(BizExpense.date.desc(), BizExpense.id.desc()).limit(cap).all()

    live_sales = [s for s in sales if s.status != "Void"]
    revenue = r2(sum(s.total - s.tax for s in live_sales))
    outstanding = r2(sum(max(s.total - s.paid, 0) for s in live_sales))
    expense_total = r2(sum(e.amount for e in expenses))

    return {
        "workspace": {"id": w.id, "name": w.name, "currency": w.currency, "plan": w.plan},
        "summary": {
            "revenue": revenue,
            "outstanding": outstanding,
            "expenses": expense_total,
            "net_cash_view": r2(revenue - expense_total),
        },
        "sales": [sale_out(s) for s in sales],
        "expenses": [exp_out(e) for e in expenses],
    }