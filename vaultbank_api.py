from collections import deque
from datetime import datetime, timedelta
import hashlib
import json
import os
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
import httpx
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

router = APIRouter(prefix="/api/bank", tags=["RMG SavannaBank"])

# ==================== STANDALONE DB & AUTH (NO CIRCULAR IMPORT WITH main.py) ====================

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./rmg_database.db")
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-rmg-key-change-this-later")
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")


class UserDB(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

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


class AuditDB(Base):
    __tablename__ = "audit_log"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String)
    action = Column(String)
    detail = Column(String)
    created_at = Column(String)


class RecordDB(Base):
    __tablename__ = "records"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String, index=True)
    data = Column(Text)
    created_at = Column(String)


def _now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _audit(db, actor: str, action: str, detail: str = ""):
    try:
        db.add(AuditDB(actor=actor, action=action, detail=detail, created_at=_now_str()))
        db.commit()
    except Exception:
        db.rollback()


def _get_revoked_map(db) -> dict:
    revoked = {}
    try:
        for r in db.query(RecordDB).filter(RecordDB.kind == "revocation").all():
            d = json.loads(r.data or "{}")
            if d.get("username"):
                revoked[d["username"]] = max(revoked.get(d["username"], 0), d.get("at", 0))
    except Exception:
        pass
    return revoked


def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            raise credentials_exception
        revoked = _get_revoked_map(db)
        if payload.get("iat", 0) < revoked.get(username, 0):
            raise HTTPException(status_code=401, detail="Session revoked")
        return user
    finally:
        db.close()


_ATTEMPTS: dict = {}


def _rate_ok(key: str, limit: int, window: int) -> bool:
    q, now = _ATTEMPTS.setdefault(key, deque()), time.time()
    while q and now - q[0] > window:
        q.popleft()
    return len(q) < limit


def _rate_hit(key: str):
    _ATTEMPTS.setdefault(key, deque()).append(time.time())


_MARKET = {"ts": 0.0, "data": None}
_FX_LIST = ["EUR", "GBP", "JPY", "CHF", "AUD", "CAD", "CNY", "INR", "ZAR", "AED", "KES", "NGN", "UGX", "TZS"]


async def _fetch_market():
    if _MARKET["data"] and time.time() - _MARKET["ts"] < 30:
        return _MARKET["data"]
    async with httpx.AsyncClient(timeout=8) as c:
        cg = await c.get(
            "https://api.coingecko.com/api/v3/coins/markets",
            params={"vs_currency": "usd", "order": "market_cap_desc", "per_page": 12, "page": 1},
        )
        fx = await c.get("https://open.er-api.com/v6/latest/USD")
    cg.raise_for_status()
    fx.raise_for_status()
    rates = fx.json().get("rates", {})
    _MARKET["data"] = {
        "crypto": [
            {
                "id": x["id"],
                "symbol": x["symbol"].upper(),
                "name": x["name"],
                "price": x["current_price"],
                "change_24h": x.get("price_change_percentage_24h") or 0,
                "high": x.get("high_24h"),
                "low": x.get("low_24h"),
                "volume": x.get("total_volume"),
            }
            for x in cg.json()
        ],
        "forex": {k: rates[k] for k in _FX_LIST if k in rates},
        "updated": _now_str(),
        "stale": False,
    }
    _MARKET["ts"] = time.time()
    return _MARKET["data"]


# ==================== BANK DATABASE MODELS ====================

class BankWalletDB(Base):
    __tablename__ = "bank_wallets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    account_number = Column(String, unique=True, index=True)
    label = Column(String)
    wallet_type = Column(String, default="Current")
    currency = Column(String, default="KES")
    balance = Column(Float, default=0.0)
    daily_limit = Column(Float, default=500000.0)
    status = Column(String, default="Active")
    is_primary = Column(Boolean, default=False)
    created_at = Column(String)


class BankTransactionDB(Base):
    __tablename__ = "bank_transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    wallet_id = Column(Integer, index=True)
    reference = Column(String, unique=True, index=True)
    tx_type = Column(String)
    channel = Column(String)
    counterparty = Column(String, default="")
    amount = Column(Float)
    fee = Column(Float, default=0.0)
    balance_after = Column(Float)
    currency = Column(String, default="KES")
    status = Column(String, default="Completed")
    note = Column(String, default="")
    created_at = Column(String)


class BankLoanDB(Base):
    __tablename__ = "bank_loans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    wallet_id = Column(Integer, index=True)
    loan_code = Column(String, unique=True, index=True)
    product_name = Column(String)
    principal = Column(Float)
    interest_rate_pct = Column(Float)
    fee_amount = Column(Float)
    total_repayable = Column(Float)
    amount_repaid = Column(Float, default=0.0)
    remaining_balance = Column(Float)
    term_days = Column(Integer, default=30)
    status = Column(String, default="Active")
    due_date = Column(String)
    created_at = Column(String)


class BankSecurityDB(Base):
    __tablename__ = "bank_security"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, index=True)
    pin_hash = Column(String, nullable=True)
    two_fa_enabled = Column(Boolean, default=True)
    require_pin_above = Column(Float, default=5000.0)
    anti_phish_phrase = Column(String, default="SAVANNA-GUARD")
    locked_until = Column(Float, default=0.0)
    updated_at = Column(String)


Base.metadata.create_all(bind=engine)


# ==================== CONSTANTS & PRICING ====================

SUPPORTED_CURRENCIES = {"KES", "USD", "EUR", "GBP", "NGN", "ZAR", "UGX", "TZS"}

FALLBACK_USD_RATES = {
    "USD": 1.0,
    "KES": 129.0,
    "EUR": 0.92,
    "GBP": 0.79,
    "NGN": 1650.0,
    "ZAR": 18.2,
    "UGX": 3720.0,
    "TZS": 2680.0,
}

LOAN_TIERS = {
    "Savanna Micro-Advance": {"max_kes": 50000.0, "rate_pct": 4.5, "fee_pct": 1.0, "term_days": 14},
    "Quick Cash Boost": {"max_kes": 150000.0, "rate_pct": 6.5, "fee_pct": 1.5, "term_days": 30},
    "SME Float Line": {"max_kes": 350000.0, "rate_pct": 8.0, "fee_pct": 1.5, "term_days": 45},
}

NSE_COUNTERS = [
    {"ticker": "SCOM", "name": "Safaricom PLC", "sector": "Telecommunications", "price": 37.05, "change_pct": 0.38, "volume": 8109142},
    {"ticker": "EQTY", "name": "Equity Group Holdings PLC", "sector": "Banking", "price": 92.25, "change_pct": -1.07, "volume": 2513348},
    {"ticker": "KCB", "name": "KCB Group PLC", "sector": "Banking", "price": 46.80, "change_pct": 1.19, "volume": 3180400},
    {"ticker": "COOP", "name": "Co-operative Bank of Kenya", "sector": "Banking", "price": 18.40, "change_pct": 0.82, "volume": 1642100},
    {"ticker": "ABSA", "name": "Absa Bank Kenya PLC", "sector": "Banking", "price": 30.10, "change_pct": -4.60, "volume": 1205900},
    {"ticker": "NCBA", "name": "NCBA Group PLC", "sector": "Banking", "price": 54.50, "change_pct": 0.93, "volume": 745000},
    {"ticker": "EABL", "name": "East African Breweries PLC", "sector": "Manufacturing & Allied", "price": 198.00, "change_pct": 1.54, "volume": 412800},
    {"ticker": "KEGN", "name": "KenGen PLC", "sector": "Energy & Petroleum", "price": 5.12, "change_pct": 2.40, "volume": 5420000},
    {"ticker": "KPLC", "name": "Kenya Power & Lighting Co.", "sector": "Energy & Petroleum", "price": 6.85, "change_pct": -0.72, "volume": 3890000},
    {"ticker": "BATK", "name": "British American Tobacco Kenya", "sector": "Agricultural", "price": 425.00, "change_pct": 0.24, "volume": 64200},
]

NSE_CACHE = {"ts": 0.0, "data": None}


def _hash_pin(pin: str) -> str:
    salt = os.getenv("BANK_PIN_SALT", "rmg-savannabank-pin-salt")
    return hashlib.sha256(f"{salt}:{pin.strip()}".encode()).hexdigest()


def _gen_acct_no() -> str:
    return "SB" + "".join(str(secrets.randbelow(10)) for _ in range(10))


def _gen_ref(prefix: str = "SVB") -> str:
    return f"{prefix}-{secrets.token_hex(5).upper()}"


def _get_fx_rates() -> dict:
    rates = dict(FALLBACK_USD_RATES)
    mdata = _MARKET.get("data") if isinstance(_MARKET, dict) else None
    if mdata and isinstance(mdata.get("forex"), dict):
        for k, v in mdata["forex"].items():
            if isinstance(v, (int, float)) and v > 0:
                rates[k.upper()] = float(v)
    return rates


def _convert(amount: float, from_curr: str, to_curr: str) -> float:
    f = from_curr.upper()
    t = to_curr.upper()
    if f == t:
        return round(amount, 2)
    rates = _get_fx_rates()
    if f not in rates or t not in rates:
        raise HTTPException(status_code=400, detail=f"Unsupported currency pair {f} -> {t}")
    usd_val = amount / rates[f]
    return round(usd_val * rates[t], 2)


def _get_or_init_security(db, user_id: int) -> BankSecurityDB:
    sec = db.query(BankSecurityDB).filter(BankSecurityDB.user_id == user_id).first()
    if not sec:
        sec = BankSecurityDB(
            user_id=user_id,
            pin_hash=None,
            two_fa_enabled=True,
            require_pin_above=5000.0,
            anti_phish_phrase="SAVANNA-GUARD",
            updated_at=_now_str(),
        )
        db.add(sec)
        db.commit()
        db.refresh(sec)
    return sec


def _ensure_starter_wallets(db, user: UserDB):
    existing = db.query(BankWalletDB).filter(BankWalletDB.user_id == user.id).all()
    if existing:
        return existing
    now = _now_str()
    w1 = BankWalletDB(
        user_id=user.id,
        account_number=_gen_acct_no(),
        label="Savanna Main KES Wallet",
        wallet_type="Current",
        currency="KES",
        balance=25000.00,
        daily_limit=500000.0,
        status="Active",
        is_primary=True,
        created_at=now,
    )
    w2 = BankWalletDB(
        user_id=user.id,
        account_number=_gen_acct_no(),
        label="Global USD Reserve",
        wallet_type="FX",
        currency="USD",
        balance=500.00,
        daily_limit=10000.0,
        status="Active",
        is_primary=False,
        created_at=now,
    )
    db.add_all([w1, w2])
    db.flush()
    db.add_all([
        BankTransactionDB(
            user_id=user.id,
            wallet_id=w1.id,
            reference=_gen_ref("DEP"),
            tx_type="deposit",
            channel="SavannaWallet",
            counterparty="RMG Welcome Grant",
            amount=25000.00,
            fee=0.0,
            balance_after=25000.00,
            currency="KES",
            status="Completed",
            note="Starter KES balance",
            created_at=now,
        ),
        BankTransactionDB(
            user_id=user.id,
            wallet_id=w2.id,
            reference=_gen_ref("DEP"),
            tx_type="deposit",
            channel="SavannaWallet",
            counterparty="RMG Welcome Grant",
            amount=500.00,
            fee=0.0,
            balance_after=500.00,
            currency="USD",
            status="Completed",
            note="Starter USD reserve",
            created_at=now,
        ),
    ])
    db.commit()
    return [w1, w2]


def _verify_tx_pin(db, user: UserDB, sec: BankSecurityDB, pin: Optional[str], amount: float, account_password: Optional[str]):
    now_ts = time.time()
    if sec.locked_until and now_ts < sec.locked_until:
        rem = int(sec.locked_until - now_ts)
        raise HTTPException(status_code=423, detail=f"Security PIN locked due to failed attempts. Try again in {rem}s.")

    needs_pin = bool(sec.pin_hash) and (amount >= (sec.require_pin_above or 0))
    if needs_pin:
        if not pin or _hash_pin(pin) != sec.pin_hash:
            fail_key = f"bank_pin:{user.id}"
            _rate_hit(fail_key)
            if not _rate_ok(fail_key, 5, 600):
                sec.locked_until = now_ts + 600
                db.commit()
                raise HTTPException(status_code=423, detail="Too many incorrect PIN attempts. Locked for 10 minutes.")
            raise HTTPException(status_code=403, detail="Invalid or missing 4–6 digit Transaction PIN")

    if account_password:
        if not _verify_password(account_password, user.hashed_password):
            raise HTTPException(status_code=403, detail="Account password verification failed")


def _wallet_dict(w: BankWalletDB) -> dict:
    return {
        "id": w.id,
        "account_number": w.account_number,
        "label": w.label,
        "wallet_type": w.wallet_type,
        "currency": w.currency,
        "balance": round(w.balance, 2),
        "daily_limit": round(w.daily_limit, 2),
        "status": w.status,
        "is_primary": bool(w.is_primary),
        "created_at": w.created_at,
    }


def _tx_dict(t: BankTransactionDB) -> dict:
    return {
        "id": t.id,
        "wallet_id": t.wallet_id,
        "reference": t.reference,
        "tx_type": t.tx_type,
        "channel": t.channel,
        "counterparty": t.counterparty,
        "amount": round(t.amount, 2),
        "fee": round(t.fee, 2),
        "balance_after": round(t.balance_after, 2),
        "currency": t.currency,
        "status": t.status,
        "note": t.note,
        "created_at": t.created_at,
    }


def _loan_dict(l: BankLoanDB) -> dict:
    return {
        "id": l.id,
        "wallet_id": l.wallet_id,
        "loan_code": l.loan_code,
        "product_name": l.product_name,
        "principal": round(l.principal, 2),
        "interest_rate_pct": l.interest_rate_pct,
        "fee_amount": round(l.fee_amount, 2),
        "total_repayable": round(l.total_repayable, 2),
        "amount_repaid": round(l.amount_repaid, 2),
        "remaining_balance": round(l.remaining_balance, 2),
        "term_days": l.term_days,
        "status": l.status,
        "due_date": l.due_date,
        "created_at": l.created_at,
    }


# ==================== REQUEST SCHEMAS ====================

class CreateWalletIn(BaseModel):
    label: str = Field(..., min_length=2, max_length=80)
    wallet_type: str = "Current"
    currency: str = Field("KES", min_length=3, max_length=3)
    initial_deposit: float = Field(0.0, ge=0)
    daily_limit: float = Field(500000.0, gt=0)


class WalletStatusIn(BaseModel):
    status: str


class DepositIn(BaseModel):
    wallet_id: int
    amount: float = Field(..., gt=0)
    channel: str = "M-Pesa"
    source_detail: str = Field("", max_length=120)
    note: str = Field("", max_length=200)
    pin: Optional[str] = None


class SendMoneyIn(BaseModel):
    from_wallet_id: int
    channel: str = "M-Pesa"
    recipient: str = Field(..., min_length=2, max_length=140)
    recipient_name: str = Field("", max_length=100)
    amount: float = Field(..., gt=0)
    note: str = Field("", max_length=200)
    pin: Optional[str] = None
    account_password: Optional[str] = None


class FxSwapIn(BaseModel):
    from_wallet_id: int
    to_wallet_id: int
    amount: float = Field(..., gt=0)
    pin: Optional[str] = None


class LoanApplyIn(BaseModel):
    wallet_id: int
    product_name: str = "Savanna Micro-Advance"
    amount: float = Field(..., gt=0)
    pin: Optional[str] = None


class LoanRepayIn(BaseModel):
    wallet_id: int
    amount: float = Field(..., gt=0)


class SecurityUpdateIn(BaseModel):
    new_pin: Optional[str] = None
    current_pin: Optional[str] = None
    two_fa_enabled: bool = True
    require_pin_above: float = Field(5000.0, ge=0)
    anti_phish_phrase: str = Field("SAVANNA-GUARD", min_length=3, max_length=40)


# ==================== OVERVIEW, WALLETS & PAYMENTS ====================

@router.get("/overview")
def bank_overview(request: Request, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        wallets = _ensure_starter_wallets(db, current_user)
        txs = (
            db.query(BankTransactionDB)
            .filter(BankTransactionDB.user_id == current_user.id)
            .order_by(BankTransactionDB.id.desc())
            .limit(25)
            .all()
        )
        loans = (
            db.query(BankLoanDB)
            .filter(BankLoanDB.user_id == current_user.id)
            .order_by(BankLoanDB.id.desc())
            .all()
        )
        sec = _get_or_init_security(db, current_user.id)

        total_kes_equiv = sum(_convert(w.balance, w.currency, "KES") for w in wallets if w.status != "Closed")
        total_usd_equiv = sum(_convert(w.balance, w.currency, "USD") for w in wallets if w.status != "Closed")
        active_debt_kes = sum(
            _convert(l.remaining_balance, "KES", "KES") for l in loans if l.status == "Active"
        )
        credit_limit_kes = 350000.0
        available_credit_kes = max(0.0, round(credit_limit_kes - active_debt_kes, 2))

        return {
            "brand": "RMG SavannaBank",
            "user": {
                "name": f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username,
                "email": current_user.email,
                "company": current_user.company_name,
            },
            "summary": {
                "net_worth_kes": round(total_kes_equiv, 2),
                "net_worth_usd": round(total_usd_equiv, 2),
                "wallet_count": len(wallets),
                "active_loans": sum(1 for l in loans if l.status == "Active"),
                "active_debt_kes": round(active_debt_kes, 2),
                "credit_limit_kes": credit_limit_kes,
                "available_credit_kes": available_credit_kes,
            },
            "wallets": [_wallet_dict(w) for w in wallets],
            "recent_transactions": [_tx_dict(t) for t in txs],
            "loans": [_loan_dict(l) for l in loans],
            "security": {
                "has_pin": bool(sec.pin_hash),
                "two_fa_enabled": bool(sec.two_fa_enabled),
                "require_pin_above": round(sec.require_pin_above or 0.0, 2),
                "anti_phish_phrase": sec.anti_phish_phrase,
                "client_ip": _client_ip(request),
            },
            "fx_rates_from_usd": _get_fx_rates(),
            "loan_tiers": LOAN_TIERS,
            "payment_channels": [
                {"id": "M-Pesa", "name": "M-Pesa (Safaricom Daraja)", "region": "Kenya / East Africa", "fee_pct": 0.5, "min_fee": 10.0, "eta": "Instant"},
                {"id": "Airtel Money", "name": "Airtel Money", "region": "Pan-African Mobile", "fee_pct": 0.5, "min_fee": 10.0, "eta": "Instant"},
                {"id": "SavannaWallet", "name": "SavannaBank Instant", "region": "Internal / Member-to-Member", "fee_pct": 0.0, "min_fee": 0.0, "eta": "Instant (Zero Fee)"},
                {"id": "Bank Transfer", "name": "PESALink / SWIFT Wire", "region": "Local & Global Banks", "fee_pct": 1.0, "min_fee": 50.0, "eta": "Instant – 24h"},
                {"id": "PayPal", "name": "PayPal Checkout & Payouts", "region": "Global / International", "fee_pct": 2.5, "min_fee": 1.0, "eta": "Near-Instant"},
                {"id": "Card", "name": "Visa / Mastercard Rail", "region": "Global Cards", "fee_pct": 1.8, "min_fee": 1.0, "eta": "Instant"},
            ],
        }
    finally:
        db.close()


@router.get("/wallets")
def get_wallets(current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        wallets = _ensure_starter_wallets(db, current_user)
        return [_wallet_dict(w) for w in wallets]
    finally:
        db.close()


@router.post("/wallets")
def create_wallet(data: CreateWalletIn, current_user: UserDB = Depends(get_current_user)):
    curr = data.currency.upper()
    if curr not in SUPPORTED_CURRENCIES:
        raise HTTPException(status_code=400, detail=f"Unsupported currency '{curr}'")
    if data.wallet_type not in ("Current", "Savings", "Vault", "FX"):
        raise HTTPException(status_code=400, detail="Invalid wallet type")

    db = SessionLocal()
    try:
        existing = _ensure_starter_wallets(db, current_user)
        if len(existing) >= 12:
            raise HTTPException(status_code=400, detail="Maximum of 12 wallets per account reached")

        acct_no = _gen_acct_no()
        while db.query(BankWalletDB).filter(BankWalletDB.account_number == acct_no).first():
            acct_no = _gen_acct_no()

        now = _now_str()
        init_amt = round(data.initial_deposit, 2)
        w = BankWalletDB(
            user_id=current_user.id,
            account_number=acct_no,
            label=data.label.strip(),
            wallet_type=data.wallet_type,
            currency=curr,
            balance=init_amt,
            daily_limit=round(data.daily_limit, 2),
            status="Active",
            is_primary=False,
            created_at=now,
        )
        db.add(w)
        db.flush()

        if init_amt > 0:
            db.add(
                BankTransactionDB(
                    user_id=current_user.id,
                    wallet_id=w.id,
                    reference=_gen_ref("DEP"),
                    tx_type="deposit",
                    channel="SavannaWallet",
                    counterparty="Opening Deposit",
                    amount=init_amt,
                    fee=0.0,
                    balance_after=init_amt,
                    currency=curr,
                    status="Completed",
                    note="Initial wallet funding",
                    created_at=now,
                )
            )
        db.commit()
        db.refresh(w)
        _audit(db, current_user.username, "BANK_WALLET_CREATE", f"{w.account_number} ({w.currency})")
        return _wallet_dict(w)
    finally:
        db.close()


@router.patch("/wallets/{wallet_id}/status")
def set_wallet_status(wallet_id: int, data: WalletStatusIn, current_user: UserDB = Depends(get_current_user)):
    if data.status not in ("Active", "Frozen", "Closed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    db = SessionLocal()
    try:
        w = db.query(BankWalletDB).filter(BankWalletDB.id == wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not w:
            raise HTTPException(status_code=404, detail="Wallet not found")
        if data.status == "Closed" and round(w.balance, 2) > 0:
            raise HTTPException(status_code=400, detail="Transfer or withdraw remaining funds before closing a wallet")
        w.status = data.status
        db.commit()
        _audit(db, current_user.username, "BANK_WALLET_STATUS", f"{w.account_number} -> {data.status}")
        return _wallet_dict(w)
    finally:
        db.close()


def _calc_channel_fee(channel: str, amount: float, currency: str) -> float:
    ch = (channel or "").strip()
    if ch == "SavannaWallet":
        return 0.0
    is_kes = currency.upper() == "KES"
    scale = 1.0 if is_kes else 0.01
    if ch in ("M-Pesa", "Airtel Money"):
        return round(max(10.0 * scale, amount * 0.005), 2)
    if ch == "Bank Transfer":
        return round(max(50.0 * scale, amount * 0.01), 2)
    if ch == "PayPal":
        return round(max(1.0 if not is_kes else 120.0, amount * 0.025), 2)
    if ch == "Card":
        return round(max(1.0 if not is_kes else 100.0, amount * 0.018), 2)
    return round(amount * 0.005, 2)


@router.post("/deposit")
def deposit_funds(data: DepositIn, current_user: UserDB = Depends(get_current_user)):
    valid_channels = {"M-Pesa", "Airtel Money", "Bank Transfer", "PayPal", "Card", "SavannaWallet"}
    if data.channel not in valid_channels:
        raise HTTPException(status_code=400, detail="Unsupported payment channel")

    db = SessionLocal()
    try:
        _ensure_starter_wallets(db, current_user)
        sec = _get_or_init_security(db, current_user.id)
        _verify_tx_pin(db, current_user, sec, data.pin, data.amount, None)

        w = db.query(BankWalletDB).filter(BankWalletDB.id == data.wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not w:
            raise HTTPException(status_code=404, detail="Wallet not found")
        if w.status != "Active":
            raise HTTPException(status_code=400, detail=f"Wallet is {w.status}")

        amt = round(data.amount, 2)
        fee = round(_calc_channel_fee(data.channel, amt, w.currency) * 0.5, 2) if data.channel != "SavannaWallet" else 0.0
        net_credit = round(max(0.01, amt - fee), 2)
        w.balance = round(w.balance + net_credit, 2)

        ref = _gen_ref("MPESA" if data.channel == "M-Pesa" else "PPL" if data.channel == "PayPal" else "DEP")
        tx = BankTransactionDB(
            user_id=current_user.id,
            wallet_id=w.id,
            reference=ref,
            tx_type="deposit",
            channel=data.channel,
            counterparty=data.source_detail.strip() or f"{data.channel} Funding",
            amount=net_credit,
            fee=fee,
            balance_after=w.balance,
            currency=w.currency,
            status="Completed",
            note=data.note.strip() or f"Top-up via {data.channel}",
            created_at=_now_str(),
        )
        db.add(tx)
        db.commit()
        db.refresh(tx)
        _audit(db, current_user.username, "BANK_DEPOSIT", f"{w.account_number} +{net_credit:.2f} {w.currency} ({data.channel})")
        return {"message": f"Deposited {net_credit:.2f} {w.currency} via {data.channel}", "wallet": _wallet_dict(w), "transaction": _tx_dict(tx)}
    finally:
        db.close()


@router.post("/send")
def send_money(data: SendMoneyIn, current_user: UserDB = Depends(get_current_user)):
    valid_channels = {"SavannaWallet", "M-Pesa", "Airtel Money", "Bank Transfer", "PayPal", "Card"}
    if data.channel not in valid_channels:
        raise HTTPException(status_code=400, detail="Unsupported transfer rail")

    db = SessionLocal()
    try:
        _ensure_starter_wallets(db, current_user)
        sec = _get_or_init_security(db, current_user.id)
        _verify_tx_pin(db, current_user, sec, data.pin, data.amount, data.account_password)

        src = db.query(BankWalletDB).filter(BankWalletDB.id == data.from_wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not src:
            raise HTTPException(status_code=404, detail="Source wallet not found")
        if src.status != "Active":
            raise HTTPException(status_code=400, detail=f"Source wallet is {src.status}")

        amt = round(data.amount, 2)
        if amt > src.daily_limit:
            raise HTTPException(status_code=400, detail=f"Amount exceeds wallet daily limit ({src.daily_limit:.2f} {src.currency})")

        fee = _calc_channel_fee(data.channel, amt, src.currency)
        total_debit = round(amt + fee, 2)
        if src.balance < total_debit:
            raise HTTPException(status_code=400, detail=f"Insufficient balance (need {total_debit:.2f} {src.currency} incl. {fee:.2f} fee)")

        now = _now_str()
        ref = _gen_ref("SND")
        target_clean = data.recipient.strip()

        dest_wallet = db.query(BankWalletDB).filter(BankWalletDB.account_number == target_clean.upper()).first()
        if dest_wallet and dest_wallet.id == src.id:
            raise HTTPException(status_code=400, detail="Cannot send funds to the same wallet")

        src.balance = round(src.balance - total_debit, 2)
        tx_type = "transfer_internal" if dest_wallet else "transfer_external"
        counterparty_label = data.recipient_name.strip() or target_clean

        out_tx = BankTransactionDB(
            user_id=current_user.id,
            wallet_id=src.id,
            reference=ref,
            tx_type=tx_type,
            channel=data.channel,
            counterparty=f"{counterparty_label} ({target_clean})",
            amount=amt,
            fee=fee,
            balance_after=src.balance,
            currency=src.currency,
            status="Completed",
            note=data.note.strip() or f"Sent via {data.channel}",
            created_at=now,
        )
        db.add(out_tx)

        if dest_wallet and dest_wallet.status == "Active":
            credited = _convert(amt, src.currency, dest_wallet.currency)
            dest_wallet.balance = round(dest_wallet.balance + credited, 2)
            db.add(
                BankTransactionDB(
                    user_id=dest_wallet.user_id,
                    wallet_id=dest_wallet.id,
                    reference=f"{ref}-CR",
                    tx_type="deposit",
                    channel="SavannaWallet",
                    counterparty=f"{current_user.first_name or current_user.username} ({src.account_number})",
                    amount=credited,
                    fee=0.0,
                    balance_after=dest_wallet.balance,
                    currency=dest_wallet.currency,
                    status="Completed",
                    note=data.note.strip() or "Incoming SavannaBank transfer",
                    created_at=now,
                )
            )

        db.commit()
        db.refresh(out_tx)
        _audit(db, current_user.username, "BANK_SEND", f"{src.account_number} -> {target_clean} {amt:.2f} {src.currency} via {data.channel}")
        return {
            "message": f"Sent {amt:.2f} {src.currency} via {data.channel} (Ref: {ref})",
            "wallet": _wallet_dict(src),
            "transaction": _tx_dict(out_tx),
        }
    finally:
        db.close()


@router.post("/fx/swap")
def fx_swap(data: FxSwapIn, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        _ensure_starter_wallets(db, current_user)
        sec = _get_or_init_security(db, current_user.id)
        _verify_tx_pin(db, current_user, sec, data.pin, data.amount, None)

        src = db.query(BankWalletDB).filter(BankWalletDB.id == data.from_wallet_id, BankWalletDB.user_id == current_user.id).first()
        dst = db.query(BankWalletDB).filter(BankWalletDB.id == data.to_wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not src or not dst:
            raise HTTPException(status_code=404, detail="Wallet not found")
        if src.id == dst.id:
            raise HTTPException(status_code=400, detail="Select two different wallets")
        if src.status != "Active" or dst.status != "Active":
            raise HTTPException(status_code=400, detail="Both wallets must be Active")

        amt = round(data.amount, 2)
        if src.balance < amt:
            raise HTTPException(status_code=400, detail="Insufficient balance in source wallet")

        converted = _convert(amt, src.currency, dst.currency)
        if converted <= 0:
            raise HTTPException(status_code=400, detail="Converted amount is too small")

        now = _now_str()
        ref = _gen_ref("FX")
        src.balance = round(src.balance - amt, 2)
        dst.balance = round(dst.balance + converted, 2)

        db.add(
            BankTransactionDB(
                user_id=current_user.id,
                wallet_id=src.id,
                reference=f"{ref}-OUT",
                tx_type="fx_swap",
                channel="FX",
                counterparty=f"Swap to {dst.currency} ({dst.account_number})",
                amount=amt,
                fee=0.0,
                balance_after=src.balance,
                currency=src.currency,
                status="Completed",
                note=f"{amt:.2f} {src.currency} -> {converted:.2f} {dst.currency}",
                created_at=now,
            )
        )
        in_tx = BankTransactionDB(
            user_id=current_user.id,
            wallet_id=dst.id,
            reference=f"{ref}-IN",
            tx_type="fx_swap",
            channel="FX",
            counterparty=f"Swap from {src.currency} ({src.account_number})",
            amount=converted,
            fee=0.0,
            balance_after=dst.balance,
            currency=dst.currency,
            status="Completed",
            note=f"{amt:.2f} {src.currency} -> {converted:.2f} {dst.currency}",
            created_at=now,
        )
        db.add(in_tx)
        db.commit()
        _audit(db, current_user.username, "BANK_FX_SWAP", f"{amt:.2f} {src.currency} -> {converted:.2f} {dst.currency}")
        return {
            "message": f"Converted {amt:.2f} {src.currency} into {converted:.2f} {dst.currency}",
            "from_wallet": _wallet_dict(src),
            "to_wallet": _wallet_dict(dst),
            "converted_amount": converted,
        }
    finally:
        db.close()


# ==================== MICRO-LOANS ====================

@router.get("/loans")
def list_loans(current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(BankLoanDB).filter(BankLoanDB.user_id == current_user.id).order_by(BankLoanDB.id.desc()).all()
        return [_loan_dict(r) for r in rows]
    finally:
        db.close()


@router.post("/loans/apply")
def apply_loan(data: LoanApplyIn, current_user: UserDB = Depends(get_current_user)):
    tier = LOAN_TIERS.get(data.product_name)
    if not tier:
        raise HTTPException(status_code=400, detail="Unknown loan product")

    db = SessionLocal()
    try:
        _ensure_starter_wallets(db, current_user)
        sec = _get_or_init_security(db, current_user.id)
        _verify_tx_pin(db, current_user, sec, data.pin, data.amount, None)

        w = db.query(BankWalletDB).filter(BankWalletDB.id == data.wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not w or w.status != "Active":
            raise HTTPException(status_code=400, detail="Select an Active wallet for loan disbursement")

        max_allowed_in_wallet_curr = _convert(tier["max_kes"], "KES", w.currency)
        min_allowed_in_wallet_curr = _convert(500.0, "KES", w.currency)
        amt = round(data.amount, 2)
        if amt < min_allowed_in_wallet_curr or amt > max_allowed_in_wallet_curr:
            raise HTTPException(
                status_code=400,
                detail=f"Loan amount must be between {min_allowed_in_wallet_curr:.2f} and {max_allowed_in_wallet_curr:.2f} {w.currency}",
            )

        active_loans = db.query(BankLoanDB).filter(BankLoanDB.user_id == current_user.id, BankLoanDB.status == "Active").all()
        if len(active_loans) >= 3:
            raise HTTPException(status_code=400, detail="You have reached the maximum of 3 active micro-loans")

        fee_amt = round(amt * (tier["fee_pct"] / 100.0), 2)
        interest_amt = round(amt * (tier["rate_pct"] / 100.0), 2)
        net_disbursed = round(max(0.01, amt - fee_amt), 2)
        total_repayable = round(amt + interest_amt, 2)

        w.balance = round(w.balance + net_disbursed, 2)
        now_dt = datetime.utcnow()
        now_str_val = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        due_str = (now_dt + timedelta(days=tier["term_days"])).strftime("%Y-%m-%d")

        loan = BankLoanDB(
            user_id=current_user.id,
            wallet_id=w.id,
            loan_code=_gen_ref("LN"),
            product_name=data.product_name,
            principal=amt,
            interest_rate_pct=tier["rate_pct"],
            fee_amount=fee_amt,
            total_repayable=total_repayable,
            amount_repaid=0.0,
            remaining_balance=total_repayable,
            term_days=tier["term_days"],
            status="Active",
            due_date=due_str,
            created_at=now_str_val,
        )
        db.add(loan)
        db.add(
            BankTransactionDB(
                user_id=current_user.id,
                wallet_id=w.id,
                reference=_gen_ref("LOAN"),
                tx_type="loan_disburse",
                channel="Loan",
                counterparty=f"SavannaBank · {data.product_name}",
                amount=net_disbursed,
                fee=fee_amt,
                balance_after=w.balance,
                currency=w.currency,
                status="Completed",
                note=f"Loan {loan.loan_code} disbursed (Due {due_str})",
                created_at=now_str_val,
            )
        )
        db.commit()
        db.refresh(loan)
        _audit(db, current_user.username, "BANK_LOAN_APPLY", f"{loan.loan_code} {amt:.2f} {w.currency}")
        return {"message": f"Disbursed {net_disbursed:.2f} {w.currency} ({loan.loan_code})", "loan": _loan_dict(loan), "wallet": _wallet_dict(w)}
    finally:
        db.close()


@router.post("/loans/{loan_id}/repay")
def repay_loan(loan_id: int, data: LoanRepayIn, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        loan = db.query(BankLoanDB).filter(BankLoanDB.id == loan_id, BankLoanDB.user_id == current_user.id).first()
        if not loan:
            raise HTTPException(status_code=404, detail="Loan not found")
        if loan.status == "Repaid" or loan.remaining_balance <= 0:
            raise HTTPException(status_code=400, detail="Loan is already repaid")

        w = db.query(BankWalletDB).filter(BankWalletDB.id == data.wallet_id, BankWalletDB.user_id == current_user.id).first()
        if not w or w.status != "Active":
            raise HTTPException(status_code=400, detail="Select an Active wallet")

        pay_amt = round(min(data.amount, loan.remaining_balance), 2)
        if w.balance < pay_amt:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance for repayment")

        w.balance = round(w.balance - pay_amt, 2)
        loan.amount_repaid = round(loan.amount_repaid + pay_amt, 2)
        loan.remaining_balance = round(max(0.0, loan.total_repayable - loan.amount_repaid), 2)
        if loan.remaining_balance <= 0.005:
            loan.remaining_balance = 0.0
            loan.status = "Repaid"

        db.add(
            BankTransactionDB(
                user_id=current_user.id,
                wallet_id=w.id,
                reference=_gen_ref("RPY"),
                tx_type="loan_repay",
                channel="Loan",
                counterparty=f"Loan Repayment · {loan.loan_code}",
                amount=pay_amt,
                fee=0.0,
                balance_after=w.balance,
                currency=w.currency,
                status="Completed",
                note=f"Repayment on {loan.loan_code}",
                created_at=_now_str(),
            )
        )
        db.commit()
        db.refresh(loan)
        _audit(db, current_user.username, "BANK_LOAN_REPAY", f"{loan.loan_code} paid {pay_amt:.2f}")
        return {"message": f"Repaid {pay_amt:.2f} {w.currency}", "loan": _loan_dict(loan), "wallet": _wallet_dict(w)}
    finally:
        db.close()


# ==================== MARKETS: CRYPTO + FOREX + NSE KENYA ====================

@router.get("/markets")
async def bank_markets(current_user: UserDB = Depends(get_current_user)):
    crypto_rows = []
    forex_rates = dict(FALLBACK_USD_RATES)
    market_stale = True
    updated_at = _now_str()

    try:
        m = await _fetch_market()
        crypto_rows = m.get("crypto") or []
        forex_rates.update(m.get("forex") or {})
        market_stale = bool(m.get("stale"))
        updated_at = m.get("updated") or updated_at
    except Exception:
        crypto_rows = [
            {"id": "bitcoin", "symbol": "BTC", "name": "Bitcoin", "price": 94250.0, "change_24h": 2.14, "volume": 38400000000},
            {"id": "ethereum", "symbol": "ETH", "name": "Ethereum", "price": 3280.0, "change_24h": 1.45, "volume": 17200000000},
            {"id": "solana", "symbol": "SOL", "name": "Solana", "price": 218.5, "change_24h": 4.22, "volume": 6100000000},
            {"id": "binancecoin", "symbol": "BNB", "name": "BNB", "price": 645.0, "change_24h": -0.65, "volume": 2100000000},
        ]

    nse_url = os.getenv("NSE_API_URL", "").strip()
    nse_key = os.getenv("NSE_API_KEY", "").strip()
    nse_rows = [dict(x) for x in NSE_COUNTERS]
    nse_live = False

    if nse_url and time.time() - NSE_CACHE["ts"] > 60:
        try:
            headers = {"X-RapidAPI-Key": nse_key} if nse_key else {}
            async with httpx.AsyncClient(timeout=6) as client:
                resp = await client.get(nse_url, headers=headers)
                if resp.status_code == 200:
                    payload = resp.json()
                    items = payload.get("data") if isinstance(payload, dict) else payload
                    if isinstance(items, list) and items:
                        parsed = [
                            {
                                "ticker": it.get("ticker", "NSE"),
                                "name": it.get("name", "NSE Listed Security"),
                                "sector": it.get("sector", "Equities"),
                                "price": float(it.get("price", 0) or 0),
                                "change_pct": float(it.get("change", 0) or 0),
                                "volume": int(float(it.get("volume", 0) or 0)),
                            }
                            for it in items[:15]
                        ]
                        if parsed:
                            NSE_CACHE["data"] = parsed
                            NSE_CACHE["ts"] = time.time()
        except Exception:
            pass

    if NSE_CACHE["data"]:
        nse_rows = NSE_CACHE["data"]
        nse_live = True

    kes_per_usd = float(forex_rates.get("KES", 129.0) or 129.0)
    enriched_crypto = [
        {**c, "price_kes": round(float(c.get("price") or 0.0) * kes_per_usd, 2)}
        for c in crypto_rows
    ]

    return {
        "updated_at": updated_at,
        "stale": market_stale,
        "crypto": enriched_crypto,
        "forex": forex_rates,
        "nse": {
            "exchange": "Nairobi Securities Exchange (NSE)",
            "indices": [
                {"name": "NSE All Share (NASI)", "value": 233.99, "change": -1.70},
                {"name": "NSE 20 Share Index", "value": 4091.92, "change": -22.79},
                {"name": "NSE 25 Share Index", "value": 6623.40, "change": -55.85},
            ],
            "stocks": nse_rows,
            "live_feed": nse_live,
        },
    }


# ==================== SECURITY & TRANSACTIONS ====================

@router.get("/transactions")
def get_transactions(wallet_id: Optional[int] = None, channel: Optional[str] = None, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        q = db.query(BankTransactionDB).filter(BankTransactionDB.user_id == current_user.id)
        if wallet_id is not None:
            q = q.filter(BankTransactionDB.wallet_id == wallet_id)
        if channel:
            q = q.filter(BankTransactionDB.channel == channel)
        rows = q.order_by(BankTransactionDB.id.desc()).limit(250).all()
        return [_tx_dict(r) for r in rows]
    finally:
        db.close()


@router.put("/security")
def update_bank_security(data: SecurityUpdateIn, request: Request, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()
    try:
        sec = _get_or_init_security(db, current_user.id)
        if data.new_pin is not None and data.new_pin.strip() != "":
            pin_clean = data.new_pin.strip()
            if not (pin_clean.isdigit() and 4 <= len(pin_clean) <= 6):
                raise HTTPException(status_code=400, detail="Transaction PIN must be 4 to 6 digits")
            if sec.pin_hash and (not data.current_pin or _hash_pin(data.current_pin.strip()) != sec.pin_hash):
                raise HTTPException(status_code=403, detail="Enter your current PIN to set a new PIN")
            sec.pin_hash = _hash_pin(pin_clean)
            sec.locked_until = 0.0

        sec.two_fa_enabled = bool(data.two_fa_enabled)
        sec.require_pin_above = round(data.require_pin_above, 2)
        sec.anti_phish_phrase = data.anti_phish_phrase.strip()
        sec.updated_at = _now_str()
        db.commit()
        _audit(db, current_user.username, "BANK_SECURITY_UPDATE", f"ip={_client_ip(request)} pin_set={bool(sec.pin_hash)}")
        return {
            "message": "SavannaBank security policy updated",
            "has_pin": bool(sec.pin_hash),
            "two_fa_enabled": sec.two_fa_enabled,
            "require_pin_above": sec.require_pin_above,
            "anti_phish_phrase": sec.anti_phish_phrase,
        }
    finally:
        db.close()
