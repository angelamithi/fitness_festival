"""
Fitness Festival 2026 — Backend Server
Python + FastAPI + PostgreSQL + M-Pesa Daraja API + JWT Auth
"""

import os
import uuid
import base64
import random
import string
import logging
import hashlib
import hmac
import ssl as ssl_lib
import smtplib
import io
import qrcode
from datetime import datetime, timezone, timedelta
from typing import Optional, AsyncGenerator

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from dotenv import load_dotenv
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from api.database import init_db, get_db, Order, CheckIn

# ─────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("fitness_festival")

app = FastAPI(title="Fitness Festival 2026 API", version="1.0.0")


@app.on_event("startup")
async def startup():
    await init_db()
    log.info("Database tables ready.")


# ─────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "https://www.fitnessfestival.co.ke",
    "https://fitnessfestival.co.ke",
    "https://fitness-festival.vercel.app",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# In-memory token store (tokens don't need to survive restarts)
# ─────────────────────────────────────────────────────────────
active_tokens: dict[str, datetime] = {}

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
class MpesaConfig:
    shortcode       = os.getenv("MPESA_SHORTCODE",       "174379")
    passkey         = os.getenv("MPESA_PASSKEY",         "YOUR_PASSKEY")
    consumer_key    = os.getenv("MPESA_CONSUMER_KEY",    "YOUR_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET", "YOUR_SECRET")
    callback_url    = os.getenv("MPESA_CALLBACK_URL",    "https://fitness-festival.onrender.com/api/mpesa/callback")
    env             = os.getenv("MPESA_ENV",             "sandbox")

    @property
    def base_url(self) -> str:
        return "https://api.safaricom.co.ke" if self.env == "production" else "https://sandbox.safaricom.co.ke"

mpesa = MpesaConfig()
IS_DEV = os.getenv("ENV", "development") != "production"

log.info(f"M-Pesa env: {mpesa.env} | shortcode: {mpesa.shortcode} | passkey length: {len(mpesa.passkey)} chars")

ADMIN_USERNAME     = os.getenv("ADMIN_USERNAME", "admin")
# Base URL of the admin dashboard — used to build QR-code check-in links.
# e.g. https://www.fitnessfestival.co.ke/admin
ADMIN_URL          = os.getenv("ADMIN_URL", "https://www.fitnessfestival.co.ke/admin")
ADMIN_PASSWORD     = os.getenv("ADMIN_PASSWORD", "festival2026")
JWT_SECRET         = os.getenv("JWT_SECRET",     "change-this-secret-in-env")
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))

# ─────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────
def make_token() -> str:
    raw = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    sig = hmac.new(JWT_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def verify_token(token: str) -> bool:
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

def hash_password(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

bearer_scheme = HTTPBearer(auto_error=False)

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not credentials or not verify_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="Not authenticated.", headers={"WWW-Authenticate": "Bearer"})
    return credentials.credentials

# ─────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TicketPurchaseRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name:        str
    phone:       str
    email:       EmailStr
    amount:      int
    ticket_type: str = Field(default="standard", alias="ticketType")
    quantity:    int = Field(default=1, ge=1, le=10)

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
    return f"{prefix}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

def get_mpesa_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")

def get_mpesa_password(timestamp: str) -> str:
    return base64.b64encode(f"{mpesa.shortcode}{mpesa.passkey}{timestamp}".encode()).decode()

def format_phone(phone: str) -> str:
    phone = phone.replace(" ", "").replace("-", "").replace("+", "")
    if phone.startswith("07") or phone.startswith("01"):
        return "254" + phone[1:]
    return phone

async def get_mpesa_token() -> str:
    creds = base64.b64encode(f"{mpesa.consumer_key}:{mpesa.consumer_secret}".encode()).decode()
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{mpesa.base_url}/oauth/v1/generate?grant_type=client_credentials",
                             headers={"Authorization": f"Basic {creds}"}, timeout=15)
        r.raise_for_status()
        data = r.json()
        if "access_token" not in data:
            raise ValueError(f"No access_token: {data}")
        return data["access_token"]

# ─────────────────────────────────────────────────────────────
# Email helper
# ─────────────────────────────────────────────────────────────
def send_ticket_email(ticket: dict, all_ticket_ids: list = None) -> None:
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    if not smtp_user or not smtp_pass:
        log.warning("SMTP not configured — skipping email.")
        return

    label     = "FREE ACCESS" if ticket["ticket_type"] == "free" else "STANDARD ENTRY"
    mpesa_row = (f'<tr><td style="padding:0.5rem 0;color:#8a9e82;">M-Pesa Ref</td>'
                 f'<td style="padding:0.5rem 0;font-family:monospace;">{ticket.get("mpesa_ref","")}</td></tr>'
                 if ticket.get("mpesa_ref") else "")

    # Build ticket ID rows — one per ticket for bulk orders
    ids_list      = all_ticket_ids if all_ticket_ids else [ticket["ticket_id"]]
    quantity      = len(ids_list)
    ticket_header = f"Your {quantity} Tickets" if quantity > 1 else "Your Ticket"
    label_line    = f"{label}  ×{quantity}" if quantity > 1 else label

    id_rows = "".join(
        f'<tr><td style="padding:0.45rem 0;color:#8a9e82;font-size:0.8rem;">' +
        (f"Ticket {i+1} of {quantity}" if quantity > 1 else "Ticket ID") +
        f'</td><td style="padding:0.45rem 0;font-family:monospace;color:#b8d432;">{tid}</td></tr>'
        for i, tid in enumerate(ids_list)
    )

    # Build one QR code block per ticket — scanned at the gate on event day.
    # Generated server-side with the qrcode library, embedded as inline base64
    # so the email has no dependency on any external image service.
    def generate_qr_base64(data: str) -> str:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

    def qr_img_tag(tid: str) -> str:
        # Encode a URL that opens the admin dashboard's Check-In page and
        # auto-submits this ticket ID — so scanning the code at the gate
        # checks the attendee in immediately, no manual typing required.
        checkin_url = f"{ADMIN_URL}?checkin={tid}"
        try:
            b64 = generate_qr_base64(checkin_url)
            src = f"data:image/png;base64,{b64}"
        except Exception as e:
            log.error(f"QR generation failed for {tid}: {e}")
            # Fallback to external service if local generation ever fails
            src = f"https://api.qrserver.com/v1/create-qr-code/?size=180x180&margin=8&data={checkin_url}"
        return (
            f'<div style="text-align:center;margin:0.75rem 0;">'
            f'<img src="{src}" alt="QR code for {tid}" width="140" height="140" '
            f'style="background:#fff;border-radius:8px;padding:6px;display:inline-block;"/>'
            f'<div style="font-family:monospace;font-size:0.75rem;color:#b8d432;margin-top:0.4rem;">{tid}</div>'
            f'</div>'
        )

    qr_blocks = "".join(qr_img_tag(tid) for tid in ids_list)

    bulk_note = (
        '<div style="background:#142418;border-radius:8px;padding:1rem;font-size:0.82rem;color:#8a9e82;margin-top:1rem;">' +
        f'Each of the {quantity} QR codes above checks in one person. Staff scan the code at the gate — no manual entry needed.' +
        '</div>'
    ) if quantity > 1 else ""

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1f0f;color:#f5f5f0;font-family:Arial,sans-serif;padding:2rem;max-width:560px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:2rem;">
    <h1 style="font-size:2.5rem;color:#b8d432;margin:0;">FITNESS FESTIVAL</h1>
    <p style="color:#8a9e82;font-size:0.85rem;letter-spacing:0.15em;text-transform:uppercase;">08 August 2026 · Nandi Hills Primary School</p>
  </div>
  <div style="background:#1a2e1c;border:1px solid rgba(184,212,50,0.2);border-radius:12px;padding:2rem;margin-bottom:1.5rem;">
    <p style="color:#8a9e82;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.25rem;">{ticket_header}</p>
    <h2 style="font-size:1.5rem;color:#b8d432;margin:0 0 1.5rem;">{label_line}</h2>
    <table style="width:100%;border-collapse:collapse;">
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Name</td><td style="padding:0.5rem 0;font-weight:600;">{ticket["name"]}</td></tr>
      {id_rows}
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Date</td><td style="padding:0.5rem 0;">Saturday, 08 August 2026</td></tr>
      <tr><td style="padding:0.5rem 0;color:#8a9e82;">Venue</td><td style="padding:0.5rem 0;">Nandi Hills Primary School, Nandi Hills</td></tr>
      {mpesa_row}
    </table>
    {bulk_note}
    <div style="border-top:1px solid rgba(184,212,50,0.15);margin-top:1.25rem;padding-top:1.25rem;">
      <p style="color:#8a9e82;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;text-align:center;margin-bottom:0.5rem;">Scan at the Gate</p>
      <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:0.5rem;">
        {qr_blocks}
      </div>
    </div>
  </div>
  <p style="color:#8a9e82;font-size:0.78rem;text-align:center;margin-top:1.5rem;">
    Powered by Eastern Produce Kenya Limited · Fitness Festival 2026<br/>
    Questions? <a href="mailto:info@fitnessfestival.co.ke" style="color:#b8d432;">info@fitnessfestival.co.ke</a>
  </p>
</body></html>"""

    tickets_word  = "Tickets" if quantity > 1 else "Ticket"
    subject_id    = f"{quantity} tickets" if quantity > 1 else ticket["ticket_id"]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"✅ Your {tickets_word} — Fitness Festival 2026 ({subject_id})"
    msg["From"]    = f'"Fitness Festival 2026" <{smtp_user}>'
    msg["To"]      = ticket["email"]
    msg.attach(MIMEText(html, "html"))

    attempts = [("smtp.gmail.com", 465, "ssl"), ("smtp.gmail.com", 587, "tls")]
    for host, port, mode in attempts:
        try:
            if mode == "ssl":
                ctx = ssl_lib.create_default_context()
                with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, ticket["email"], msg.as_string())
            else:
                with smtplib.SMTP(host, port, timeout=15) as s:
                    s.starttls(); s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, ticket["email"], msg.as_string())
            log.info(f"Email sent → {ticket['email']} ({ticket['ticket_id']})")
            return
        except Exception as e:
            log.warning(f"Email via {host}:{port} failed: {e}")
    raise Exception("All email attempts failed")

# ─────────────────────────────────────────────────────────────
# Helpers — convert DB row to dict
# ─────────────────────────────────────────────────────────────
def order_to_dict(o: Order) -> dict:
    ticket_ids = o.ticket_id.split(",") if o.ticket_id else []
    return {
        "order_id":            o.order_id,
        "ticket_id":           o.ticket_id,
        "ticket_ids":          ticket_ids,
        "quantity":            len(ticket_ids),
        "name":                o.name,
        "phone":               o.phone,
        "email":               o.email,
        "amount":              o.amount,
        "ticket_type":         o.ticket_type,
        "status":              o.status,
        "checkout_request_id": o.checkout_request_id,
        "mpesa_ref":           o.mpesa_ref,
        "failure_reason":      o.failure_reason,
        "created_at":          o.created_at.isoformat() if o.created_at else None,
        "paid_at":             o.paid_at.isoformat() if o.paid_at else None,
        "amount_paid":         o.amount_paid,
    }

# ─────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────
@app.post("/api/admin/login")
async def admin_login(body: LoginRequest):
    ok_user = hmac.compare_digest(body.username.strip(), ADMIN_USERNAME)
    ok_pass = hmac.compare_digest(hash_password(body.password), hash_password(ADMIN_PASSWORD))
    if not (ok_user and ok_pass):
        log.warning(f"Failed login: '{body.username}'")
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token  = make_token()
    expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    active_tokens[token] = expiry
    return {"token": token, "expires_at": expiry.isoformat(), "message": "Login successful."}

@app.post("/api/admin/logout")
async def admin_logout(token: str = Depends(require_admin)):
    active_tokens.pop(token, None)
    return {"message": "Logged out."}

@app.get("/api/admin/verify")
async def admin_verify(token: str = Depends(require_admin)):
    expiry = active_tokens.get(token)
    return {"valid": True, "expires_at": expiry.isoformat() if expiry else None}

# ─────────────────────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────
@app.post("/api/mpesa/stk-push")
async def stk_push(body: TicketPurchaseRequest, db: AsyncSession = Depends(get_db)):
    order_id   = str(uuid.uuid4())
    quantity   = max(1, min(10, body.quantity))
    # Generate one unique ticket ID per ticket in the order
    ticket_ids = [generate_ticket_id() for _ in range(quantity)]
    ticket_id  = ",".join(ticket_ids)  # stored as e.g. "TKT-AB12CD,TKT-EF34GH"

    order = Order(
        order_id    = order_id,
        ticket_id   = ticket_id,
        name        = body.name,
        phone       = body.phone,
        email       = body.email,
        amount      = body.amount,  # frontend already sends total (price x qty)
        ticket_type = body.ticket_type,
        status      = "pending",
    )
    db.add(order)
    await db.commit()

    # Simulate mode
    if os.getenv("MPESA_SIMULATE", "false").lower() == "true":
        order.checkout_request_id = f"sim_{order_id}"
        await db.commit()
        return {"success": True, "order_id": order_id, "message": "STK push sent (simulation)."}

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
                    "TransactionDesc":   f"Fitness Festival 2026 - {ticket_id}",
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )

        log.info(f"Safaricom STK {stk_res.status_code}: {stk_res.text}")
        stk_data = stk_res.json()

        if stk_data.get("ResponseCode") == "0":
            order.checkout_request_id = stk_data["CheckoutRequestID"]
            await db.commit()
            return {"success": True, "order_id": order_id, "message": "STK push sent."}
        else:
            order.status = "failed"
            await db.commit()
            raise HTTPException(status_code=400, detail=stk_data.get("ResponseDescription", "STK push failed."))

    except httpx.HTTPError as exc:
        log.error(f"M-Pesa error: {exc}")
        order.status = "failed"
        await db.commit()
        raise HTTPException(status_code=502, detail=f"M-Pesa unreachable: {type(exc).__name__}")
    except Exception as exc:
        log.exception(f"Unexpected STK error: {exc}")
        order.status = "failed"
        await db.commit()
        raise HTTPException(status_code=500, detail=str(exc)[:200])


@app.post("/api/mpesa/callback")
async def mpesa_callback(request: Request, db: AsyncSession = Depends(get_db)):
    body     = await request.json()
    callback = body.get("Body", {}).get("stkCallback", {})
    if not callback:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    result_code         = callback.get("ResultCode")
    checkout_request_id = callback.get("CheckoutRequestID")

    result = await db.execute(select(Order).where(Order.checkout_request_id == checkout_request_id))
    order  = result.scalar_one_or_none()
    if not order:
        return {"ResultCode": 0, "ResultDesc": "Order not found"}

    if result_code == 0:
        meta = {item["Name"]: item.get("Value") for item in callback.get("CallbackMetadata", {}).get("Item", [])}
        order.status      = "completed"
        order.mpesa_ref   = meta.get("MpesaReceiptNumber")
        order.paid_at     = datetime.now(timezone.utc)
        order.amount_paid = meta.get("Amount")
        await db.commit()
        try:
            od = order_to_dict(order)
            send_ticket_email(od, all_ticket_ids=od["ticket_ids"])
        except Exception as e:
            log.error(f"Email failed: {e}")
        log.info(f"Payment completed order={order.order_id} ref={order.mpesa_ref}")
    else:
        # Ignore automatic sandbox failure callbacks
        if mpesa.env == "sandbox":
            log.info(f"[SANDBOX] Ignoring failure callback for order={order.order_id}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}
        order.status         = "failed"
        order.failure_reason = callback.get("ResultDesc", "Unknown")
        await db.commit()
        log.warning(f"Payment failed order={order.order_id}")

    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@app.post("/api/mpesa/simulate/{order_id}")
async def simulate_payment(order_id: str, db: AsyncSession = Depends(get_db)):
    if mpesa.env == "production":
        raise HTTPException(status_code=403, detail="Simulation not allowed in production.")

    result = await db.execute(select(Order).where(Order.order_id == order_id))
    order  = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    if order.status == "completed":
        return {"message": "Already completed.", "order_id": order_id}

    fake_ref              = "SIM" + "".join(random.choices(string.ascii_uppercase + string.digits, k=9))
    order.status          = "completed"
    order.mpesa_ref       = fake_ref
    order.paid_at         = datetime.now(timezone.utc)
    order.amount_paid     = order.amount
    await db.commit()

    try:
        od = order_to_dict(order)
        send_ticket_email(od, all_ticket_ids=od["ticket_ids"])
    except Exception as e:
        log.error(f"Email failed: {e}")

    log.info(f"[SIMULATE] order={order_id} ref={fake_ref}")
    return {"message": "Simulated.", "order_id": order_id, "mpesa_ref": fake_ref, "status": "completed"}


@app.get("/api/mpesa/status/{order_id}")
async def payment_status(order_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Order).where(Order.order_id == order_id))
    order  = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    return {"status": order.status, "ticket_id": order.ticket_id, "mpesa_ref": order.mpesa_ref}


@app.post("/api/register-free")
async def register_free(body: FreeTicketRequest, db: AsyncSession = Depends(get_db)):
    ticket_id = generate_ticket_id("TKT-FREE")
    order = Order(
        order_id    = str(uuid.uuid4()),
        ticket_id   = ticket_id,
        name        = body.name,
        phone       = body.phone or "",
        email       = body.email,
        amount      = 0,
        ticket_type = "free",
        status      = "completed",
        paid_at     = datetime.now(timezone.utc),
    )
    db.add(order)
    await db.commit()
    email_sent = True
    try:
        send_ticket_email(order_to_dict(order))
    except Exception as e:
        log.error(f"Email failed: {e}")
        email_sent = False
    return {"success": True, "ticket_id": ticket_id, "email_sent": email_sent}


@app.get("/api/qr/{ticket_id}")
async def get_qr_code(ticket_id: str):
    """
    Generate a QR code for a given ticket ID, server-side.
    Encodes a check-in URL (not just the raw ID) so scanning the code
    at the gate opens the admin Check-In page and submits it automatically.
    Returns a PNG image directly — used by the admin dashboard's
    download-ticket feature so it never depends on an external QR service.
    """
    from fastapi.responses import Response
    checkin_url = f"{ADMIN_URL}?checkin={ticket_id}"
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(checkin_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return Response(content=buf.getvalue(), media_type="image/png")
    except Exception as e:
        log.error(f"QR endpoint failed for {ticket_id}: {e}")
        raise HTTPException(status_code=500, detail="Could not generate QR code.")


@app.get("/api/health")
def health():
    return {
        "status":          "ok",
        "service":         "Fitness Festival 2026",
        "env":             os.getenv("ENV", "development"),
        "smtp_configured": bool(os.getenv("SMTP_USER") and os.getenv("SMTP_PASS")),
        "db":              "postgresql",
    }

# ─────────────────────────────────────────────────────────────
# PROTECTED ADMIN ROUTES
# ─────────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
async def admin_stats(token: str = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result     = await db.execute(select(Order))
    all_orders = result.scalars().all()
    completed  = [o for o in all_orders if o.status == "completed"]

    # Count individual tickets (bulk orders have comma-separated IDs)
    def ticket_count(o: Order) -> int:
        return len(o.ticket_id.split(",")) if o.ticket_id else 1

    total_tickets    = sum(ticket_count(o) for o in completed)
    standard_tickets = sum(ticket_count(o) for o in completed if o.ticket_type == "standard")
    free_tickets     = sum(ticket_count(o) for o in completed if o.ticket_type == "free")
    revenue          = sum(o.amount for o in completed if o.ticket_type != "free")

    return {
        "total":          len(completed),          # number of orders
        "total_tickets":  total_tickets,            # number of individual tickets
        "revenue":        revenue,
        "standard":       standard_tickets,
        "free":           free_tickets,
        "pending":        sum(1 for o in all_orders if o.status == "pending"),
        "failed":         sum(1 for o in all_orders if o.status == "failed"),
    }


@app.get("/api/admin/tickets")
async def admin_tickets(token: str = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Order).order_by(Order.created_at.desc()))
    orders = result.scalars().all()
    return [order_to_dict(o) for o in orders]


# ─────────────────────────────────────────────────────────────
# CHECK-IN ROUTES
# ─────────────────────────────────────────────────────────────

@app.post("/api/checkin/{ticket_id}")
async def check_in_ticket(ticket_id: str, db: AsyncSession = Depends(get_db)):
    """
    Check in a single ticket by its ID. This is what both the QR-code scan
    page and the manual admin Check-In box call. Idempotent: scanning an
    already-checked-in ticket returns its original check-in time rather
    than erroring or duplicating.
    """
    # Find the order this ticket belongs to (ticket_id may be inside a
    # comma-separated list on a bulk order)
    result = await db.execute(
        select(Order).where(Order.ticket_id.like(f"%{ticket_id}%"))
    )
    orders = result.scalars().all()
    order = next(
        (o for o in orders if ticket_id in [t.strip() for t in o.ticket_id.split(",")]),
        None,
    )
    if not order:
        raise HTTPException(status_code=404, detail="Ticket ID not found.")

    if order.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"This ticket's payment is {order.status}, not completed. Cannot check in.",
        )

    # Already checked in?
    existing = await db.execute(select(CheckIn).where(CheckIn.ticket_id == ticket_id))
    existing_row = existing.scalar_one_or_none()
    if existing_row:
        return {
            "success":       True,
            "already_checked_in": True,
            "ticket_id":     ticket_id,
            "name":          existing_row.name,
            "ticket_type":   existing_row.ticket_type,
            "checked_in_at": existing_row.checked_in_at.isoformat(),
        }

    checkin = CheckIn(
        ticket_id=ticket_id,
        order_id=order.order_id,
        name=order.name,
        ticket_type=order.ticket_type,
    )
    db.add(checkin)
    await db.commit()
    log.info(f"Checked in ticket={ticket_id} name={order.name}")

    return {
        "success":             True,
        "already_checked_in":  False,
        "ticket_id":           ticket_id,
        "name":                order.name,
        "ticket_type":         order.ticket_type,
        "checked_in_at":       checkin.checked_in_at.isoformat() if checkin.checked_in_at else datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/admin/checkins")
async def list_checkins(token: str = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """All check-ins so far today, most recent first — powers the admin Check-In page table."""
    result = await db.execute(select(CheckIn).order_by(CheckIn.checked_in_at.desc()))
    rows = result.scalars().all()
    return [
        {
            "ticket_id":     r.ticket_id,
            "order_id":      r.order_id,
            "name":          r.name,
            "ticket_type":   r.ticket_type,
            "checked_in_at": r.checked_in_at.isoformat() if r.checked_in_at else None,
        }
        for r in rows
    ]


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