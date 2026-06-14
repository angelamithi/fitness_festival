"""
Fitness Festival 2026 — Backend Server
Python + FastAPI + M-Pesa Daraja API + JWT Auth

Install dependencies:
    pip install -r requirements.txt

Run (development):
    uvicorn api.main:app --reload --port 8000

Run (production):
    uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

import os
import uuid
import base64
import random
import string
import logging
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from dotenv import load_dotenv
from pathlib import Path

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("fitness_festival")

app = FastAPI(title="Fitness Festival 2026 API", version="1.0.0")

# Allowed frontend origins — hardcoded here, no .env variable needed
# Add any extra domains below if you connect a custom domain later
ALLOWED_ORIGINS = [
    "https://fitness-festival.vercel.app",   # Vercel production
    "http://localhost:3000",                  # local dev
    "http://localhost:8000",                  # local FastAPI dev
    "http://127.0.0.1:5500",                 # VS Code Live Server
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# In-memory stores  (swap for SQLite/PostgreSQL in production)
# ─────────────────────────────────────────────────────────────
orders:  dict[str, dict] = {}
tickets: dict[str, dict] = {}

# Active tokens: token_value → expiry datetime
active_tokens: dict[str, datetime] = {}


# ─────────────────────────────────────────────────────────────
# Config  (all read from .env — never hardcoded here)
# ─────────────────────────────────────────────────────────────
class MpesaConfig:
    shortcode       = os.getenv("MPESA_SHORTCODE",       "174379")
    passkey         = os.getenv("MPESA_PASSKEY",         "YOUR_PASSKEY")
    consumer_key    = os.getenv("MPESA_CONSUMER_KEY",    "YOUR_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET", "YOUR_SECRET")
    callback_url    = os.getenv("MPESA_CALLBACK_URL",    "https://yourdomain.com/api/mpesa/callback")
    env             = os.getenv("MPESA_ENV",             "sandbox")

    @property
    def base_url(self) -> str:
        return (
            "https://api.safaricom.co.ke"
            if self.env == "production"
            else "https://sandbox.safaricom.co.ke"
        )

mpesa = MpesaConfig()
IS_DEV = os.getenv("ENV", "development") != "production"

# Admin credentials — set these in your .env file
ADMIN_USERNAME  = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD", "festival2026")   # change in .env!
JWT_SECRET      = os.getenv("JWT_SECRET",     "change-this-secret-in-env")
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))


# ─────────────────────────────────────────────────────────────
# Simple token helpers  (no extra library needed)
# We generate a signed random token and store it server-side.
# ─────────────────────────────────────────────────────────────
def make_token() -> str:
    """Generate a cryptographically random token."""
    raw = secrets_token()
    # Sign it with our JWT_SECRET so we can verify it without DB lookup
    sig = hmac.new(JWT_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def secrets_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

def verify_token(token: str) -> bool:
    """Check token signature and expiry."""
    try:
        raw, sig = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(JWT_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    expiry = active_tokens.get(token)
    if expiry is None or datetime.now(timezone.utc) > expiry:
        active_tokens.pop(token, None)
        return False
    return True

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Bearer token extractor
bearer_scheme = HTTPBearer(auto_error=False)

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """FastAPI dependency — protects any route that needs admin access."""
    if not credentials or not verify_token(credentials.credentials):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


# ─────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TicketPurchaseRequest(BaseModel):
    # populate_by_name lets us use either the alias (ticketType from JS)
    # or the field name (ticket_type from Python) — both work
    model_config = ConfigDict(populate_by_name=True)

    name:        str
    phone:       str
    email:       EmailStr
    amount:      int
    ticket_type: str = Field(default="standard", alias="ticketType")

class FreeTicketRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name:        str
    phone:       Optional[str] = None
    email:       EmailStr
    ticket_type: str = Field(default="free", alias="ticketType")


# ─────────────────────────────────────────────────────────────
# M-Pesa helpers
# ─────────────────────────────────────────────────────────────
def generate_ticket_id(prefix: str = "TKT") -> str:
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"{prefix}-{suffix}"

def get_mpesa_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")

def get_mpesa_password(timestamp: str) -> str:
    raw = f"{mpesa.shortcode}{mpesa.passkey}{timestamp}"
    return base64.b64encode(raw.encode()).decode()

def format_phone(phone: str) -> str:
    phone = phone.replace(" ", "").replace("-", "")
    if phone.startswith("07") or phone.startswith("01"):
        return "254" + phone[1:]
    if phone.startswith("+254"):
        return phone[1:]
    return phone

async def get_mpesa_token() -> str:
    credentials = base64.b64encode(
        f"{mpesa.consumer_key}:{mpesa.consumer_secret}".encode()
    ).decode()
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{mpesa.base_url}/oauth/v1/generate?grant_type=client_credentials",
            headers={"Authorization": f"Basic {credentials}"},
            timeout=15,
        )
        response.raise_for_status()
        return response.json()["access_token"]


# ─────────────────────────────────────────────────────────────
# Email helper
# ─────────────────────────────────────────────────────────────
def send_ticket_email(ticket: dict) -> None:
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        log.warning("SMTP credentials not set — skipping email.")
        return

    label = "FREE ACCESS" if ticket["ticket_type"] == "free" else "STANDARD ENTRY"
    mpesa_row = (
        f'<tr><td style="padding:0.5rem 0;color:#8a9e82;">M-Pesa Ref</td>'
        f'<td style="padding:0.5rem 0;font-family:monospace;">{ticket.get("mpesa_ref","")}</td></tr>'
        if ticket.get("mpesa_ref") else ""
    )

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1f0f;color:#f5f5f0;font-family:Arial,sans-serif;padding:2rem;max-width:560px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:2rem;">
    <h1 style="font-size:2.5rem;color:#b8d432;margin:0;">FITNESS FESTIVAL</h1>
    <p style="color:#8a9e82;font-size:0.85rem;letter-spacing:0.15em;text-transform:uppercase;">08 August 2026 · Nandi Bears Club</p>
  </div>
  <div style="background:#1a2e1c;border:1px solid rgba(184,212,50,0.2);border-radius:12px;padding:2rem;margin-bottom:1.5rem;">
    <p style="color:#8a9e82;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.25rem;">Your Ticket</p>
    <h2 style="font-size:1.5rem;color:#b8d432;margin:0 0 1.5rem;">{label}</h2>
    <table style="width:100%;border-collapse:collapse;">
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Name</td><td style="padding:0.5rem 0;font-weight:600;">{ticket["name"]}</td></tr>
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Ticket ID</td><td style="padding:0.5rem 0;font-family:monospace;color:#b8d432;">{ticket["ticket_id"]}</td></tr>
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Date</td><td style="padding:0.5rem 0;">Saturday, 08 August 2026</td></tr>
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Gates Open</td><td style="padding:0.5rem 0;">6:30 AM</td></tr>
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Venue</td><td style="padding:0.5rem 0;">Nandi Bears Club, Nandi Hills</td></tr>
      {mpesa_row}
    </table>
  </div>
  <div style="background:#142418;border-radius:8px;padding:1.25rem;font-size:0.85rem;color:#8a9e82;line-height:1.6;">
    <strong style="color:#f5f5f0;">What to bring:</strong> This email, comfortable workout gear, water bottle, and your energy!
  </div>
  <p style="color:#8a9e82;font-size:0.78rem;text-align:center;margin-top:1.5rem;">
    Powered by Eastern Produce Kenya Limited · Fitness Festival 2026<br/>
    Questions? <a href="mailto:info@fitnessfestival.co.ke" style="color:#b8d432;">info@fitnessfestival.co.ke</a>
  </p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"✅ Your Ticket — The Fitness Festival 2026 ({ticket['ticket_id']})"
    msg["From"]    = f'"Fitness Festival 2026" <{smtp_user}>'
    msg["To"]      = ticket["email"]
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, ticket["email"], msg.as_string())

    log.info(f"Ticket email sent → {ticket['email']} ({ticket['ticket_id']})")


# ─────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
async def admin_login(body: LoginRequest):
    """
    Validate admin credentials from .env and return a signed token.
    The token expires after TOKEN_EXPIRE_HOURS (default 8 hours).
    """
    username_ok = hmac.compare_digest(body.username.strip(), ADMIN_USERNAME)
    password_ok = hmac.compare_digest(
        hash_password(body.password),
        hash_password(ADMIN_PASSWORD)
    )

    if not (username_ok and password_ok):
        log.warning(f"Failed admin login attempt for username: '{body.username}'")
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token  = make_token()
    expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    active_tokens[token] = expiry

    log.info(f"Admin logged in. Token expires at {expiry.isoformat()}")
    return {
        "token":      token,
        "expires_at": expiry.isoformat(),
        "message":    "Login successful.",
    }


@app.post("/api/admin/logout")
async def admin_logout(token: str = Depends(require_admin)):
    """Invalidate the current token immediately."""
    active_tokens.pop(token, None)
    log.info("Admin logged out.")
    return {"message": "Logged out successfully."}


@app.get("/api/admin/verify")
async def admin_verify(token: str = Depends(require_admin)):
    """Let the frontend check if its stored token is still valid."""
    expiry = active_tokens.get(token)
    return {"valid": True, "expires_at": expiry.isoformat() if expiry else None}


# ─────────────────────────────────────────────────────────────
# PUBLIC ROUTES  (no auth needed)
# ─────────────────────────────────────────────────────────────

@app.post("/api/mpesa/stk-push")
async def stk_push(body: TicketPurchaseRequest):
    order_id  = str(uuid.uuid4())
    ticket_id = generate_ticket_id()

    orders[order_id] = {
        "order_id":            order_id,
        "ticket_id":           ticket_id,
        "name":                body.name,
        "phone":               body.phone,
        "email":               body.email,
        "amount":              body.amount,
        "ticket_type":         body.ticket_type,
        "status":              "pending",
        "created_at":          datetime.now(timezone.utc).isoformat(),
        "checkout_request_id": None,
        "mpesa_ref":           None,
    }

    try:
        token     = await get_mpesa_token()
        timestamp = get_mpesa_timestamp()
        password  = get_mpesa_password(timestamp)
        phone_fmt = format_phone(body.phone)

        async with httpx.AsyncClient() as client:
            stk_res = await client.post(
                f"{mpesa.base_url}/mpesa/stkpush/v1/processrequest",
                json={
                    "BusinessShortCode": mpesa.shortcode,
                    "Password":          password,
                    "Timestamp":         timestamp,
                    "TransactionType":   "CustomerPayBillOnline",
                    "Amount":            body.amount,
                    "PartyA":            phone_fmt,
                    "PartyB":            mpesa.shortcode,
                    "PhoneNumber":       phone_fmt,
                    "CallBackURL":       mpesa.callback_url,
                    "AccountReference":  ticket_id,
                    "TransactionDesc":   f"Fitness Festival 2026 Ticket - {ticket_id}",
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
            stk_res.raise_for_status()
            stk_data = stk_res.json()

        if stk_data.get("ResponseCode") == "0":
            orders[order_id]["checkout_request_id"] = stk_data["CheckoutRequestID"]
            log.info(f"STK push sent  order={order_id}")
            return {"success": True, "order_id": order_id, "message": "STK push sent to your phone."}
        else:
            orders[order_id]["status"] = "failed"
            raise HTTPException(status_code=400, detail=stk_data.get("ResponseDescription", "STK push failed."))

    except httpx.HTTPError as exc:
        log.error(f"M-Pesa HTTP error: {exc}")
        if IS_DEV:
            log.warning(f"[DEV] Simulating STK push for order {order_id}")
            return {"success": True, "order_id": order_id, "message": "STK push sent (dev mode)."}
        orders[order_id]["status"] = "failed"
        raise HTTPException(status_code=502, detail="M-Pesa service unavailable. Please try again.")


@app.post("/api/mpesa/callback")
async def mpesa_callback(request: Request):
    body     = await request.json()
    callback = body.get("Body", {}).get("stkCallback", {})
    if not callback:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    result_code         = callback.get("ResultCode")
    checkout_request_id = callback.get("CheckoutRequestID")

    order = next(
        (o for o in orders.values() if o.get("checkout_request_id") == checkout_request_id),
        None,
    )
    if not order:
        return {"ResultCode": 0, "ResultDesc": "Order not found"}

    if result_code == 0:
        meta_items = callback.get("CallbackMetadata", {}).get("Item", [])
        meta = {item["Name"]: item.get("Value") for item in meta_items}
        order["status"]      = "completed"
        order["mpesa_ref"]   = meta.get("MpesaReceiptNumber")
        order["paid_at"]     = datetime.now(timezone.utc).isoformat()
        order["amount_paid"] = meta.get("Amount")
        tickets[order["ticket_id"]] = dict(order)
        try:
            send_ticket_email(order)
        except Exception as e:
            log.error(f"Email failed: {e}")
        log.info(f"Payment completed  order={order['order_id']}  ref={order['mpesa_ref']}")
    else:
        order["status"]         = "failed"
        order["failure_reason"] = callback.get("ResultDesc", "Unknown")
        log.warning(f"Payment failed  order={order['order_id']}")

    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@app.get("/api/mpesa/status/{order_id}")
async def payment_status(order_id: str):
    order = orders.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    if IS_DEV and order["status"] == "pending":
        created     = datetime.fromisoformat(order["created_at"])
        age_seconds = (datetime.now(timezone.utc) - created).total_seconds()
        if age_seconds > 10:
            order["status"]    = "completed"
            order["mpesa_ref"] = "QHX" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            tickets[order["ticket_id"]] = dict(order)

    return {
        "status":    order["status"],
        "ticket_id": order["ticket_id"],
        "mpesa_ref": order.get("mpesa_ref"),
    }


@app.post("/api/register-free")
async def register_free(body: FreeTicketRequest):
    ticket_id = generate_ticket_id("TKT-FREE")
    ticket = {
        "ticket_id":   ticket_id,
        "name":        body.name,
        "phone":       body.phone or "",
        "email":       body.email,
        "ticket_type": "free",
        "amount":      0,
        "status":      "completed",
        "mpesa_ref":   None,
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    tickets[ticket_id] = ticket
    email_sent = True
    try:
        send_ticket_email(ticket)
    except Exception as e:
        log.error(f"Email failed: {e}")
        email_sent = False
    return {"success": True, "ticket_id": ticket_id, "email_sent": email_sent}


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Fitness Festival 2026", "env": os.getenv("ENV", "development")}


# ─────────────────────────────────────────────────────────────
# PROTECTED ADMIN ROUTES  (require valid token)
# ─────────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
def admin_stats(token: str = Depends(require_admin)):
    all_orders = list(orders.values())
    completed  = [o for o in all_orders if o["status"] == "completed"]
    revenue    = sum(o["amount"] for o in completed if o["ticket_type"] != "free")
    return {
        "total":    len(completed),
        "revenue":  revenue,
        "standard": sum(1 for o in completed if o["ticket_type"] == "standard"),
        "free":     sum(1 for o in completed if o["ticket_type"] == "free"),
        "pending":  sum(1 for o in all_orders if o["status"] == "pending"),
        "failed":   sum(1 for o in all_orders if o["status"] == "failed"),
    }


@app.get("/api/admin/tickets")
def admin_tickets(token: str = Depends(require_admin)):
    return sorted(orders.values(), key=lambda o: o["created_at"], reverse=True)


# ─────────────────────────────────────────────────────────────
# Static file serving
# ─────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
public_dir = BASE_DIR / "public"
admin_dir  = BASE_DIR / "admin"

if public_dir.exists():
    if admin_dir.exists():
        app.mount("/admin", StaticFiles(directory=str(admin_dir), html=True), name="admin")
    app.mount("/", StaticFiles(directory=str(public_dir), html=True), name="public")