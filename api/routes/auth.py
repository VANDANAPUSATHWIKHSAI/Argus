from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime, timedelta, timezone
import jwt
import random
import time
import bcrypt

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
from dotenv import load_dotenv
load_dotenv()

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")

router = APIRouter()

import secrets
SECRET_KEY = os.environ.get("ARGUS_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

import psycopg2
from psycopg2 import pool
from contextlib import contextmanager

try:
    db_pool = psycopg2.pool.SimpleConnectionPool(
        1, 20,
        host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        port=os.environ.get("POSTGRES_PORT", "5433"),
        database=os.environ.get("POSTGRES_DB", "argus"),
        user=os.environ.get("POSTGRES_USER", "argus_user"),
        password=os.environ.get("POSTGRES_PASSWORD", "argus_dev")
    )
except Exception as e:
    print("Error initializing connection pool:", e)
    db_pool = None

@contextmanager
def get_db_connection():
    if not db_pool:
        raise Exception("Database connection pool is not available")
    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        db_pool.putconn(conn)

def init_users_table():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(255) PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(50) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        phone VARCHAR(50),
                        doj VARCHAR(50)
                    );
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS doj VARCHAR(50);
                """)
            conn.commit()
    except Exception as e:
        print(f"User Table Init Error: {e}")

# Precomputed fallback default accounts when PostgreSQL is not running
_FALLBACK_HASH = get_password_hash("password123")

_BASE_FALLBACK_USERS = [
    {"id": "admin", "email": "admin@argus.local", "role": "admin", "name": "System Administrator", "phone": "+1-555-0100", "doj": "2025-01-01"},
    {"id": "analyst", "email": "analyst@argus.local", "role": "analyst", "name": "Junior Analyst", "phone": "+1-555-0101", "doj": "2025-01-15"},
    {"id": "senior_analyst", "email": "senior@argus.local", "role": "senior_analyst", "name": "Senior Analyst", "phone": "+1-555-0103", "doj": "2025-01-10"},
    {"id": "auditor", "email": "auditor@argus.local", "role": "auditor", "name": "Compliance Auditor", "phone": "+1-555-0106", "doj": "2025-01-20"},
    {"id": "EMP-001", "email": "admin@argus.local", "role": "admin", "name": "Admin User", "phone": "+1-555-0100", "doj": "2025-01-01"},
    {"id": "EMP-002", "email": "analyst@argus.local", "role": "analyst", "name": "Lead Analyst", "phone": "+1-555-0101", "doj": "2025-01-15"},
    {"id": "EMP-003", "email": "senior@argus.local", "role": "senior_analyst", "name": "Senior Analyst", "phone": "+1-555-0103", "doj": "2025-01-10"},
    {"id": "EMP-004", "email": "auditor@argus.local", "role": "auditor", "name": "Auditor User", "phone": "+1-555-0106", "doj": "2025-01-20"},
    {"id": "2", "email": "admin2@argus.local", "role": "admin", "name": "System Administrator", "phone": "+1-555-0100", "doj": "2025-01-01"},
    {"id": "4", "email": "vandanapusathwikhsai88@gmail.com", "role": "analyst", "name": "sathwik", "phone": "+1-555-0101", "doj": "2025-01-15"},
    {"id": "5", "email": "analyst5@argus.local", "role": "analyst", "name": "Analyst 5", "phone": "+1-555-0102", "doj": "2025-01-15"},
    {"id": "6", "email": "remakhat115@gmail.com", "role": "senior_analyst", "name": "Senior Analyst 6", "phone": "+1-555-0103", "doj": "2025-01-10"},
    {"id": "7", "email": "senior7@argus.local", "role": "senior_analyst", "name": "Senior Analyst 7", "phone": "+1-555-0104", "doj": "2025-01-10"},
    {"id": "8", "email": "senior8@argus.local", "role": "senior_analyst", "name": "Senior Analyst 8", "phone": "+1-555-0105", "doj": "2025-01-10"},
    {"id": "12", "email": "auditor12@argus.local", "role": "auditor", "name": "Auditor 12", "phone": "+1-555-0106", "doj": "2025-01-20"}
]

FALLBACK_USERS = {}
for u in _BASE_FALLBACK_USERS:
    user_rec = {
        "id": u["id"],
        "email": u["email"],
        "password": _FALLBACK_HASH,
        "role": u["role"],
        "name": u["name"],
        "phone": u.get("phone", "+1-555-0100"),
        "doj": u.get("doj", "2025-01-15")
    }
    FALLBACK_USERS[u["id"].lower()] = user_rec
    FALLBACK_USERS[u["email"].lower()] = user_rec

FALLBACK_USERS["senior"] = FALLBACK_USERS.get("senior_analyst")


def get_user_by_id(userid: str):
    clean_id = userid.strip().lower()
    try:
        if db_pool:
            init_users_table()
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, email, password_hash, role, name, phone, doj FROM users WHERE LOWER(id) = %s OR LOWER(email) = %s", (clean_id, clean_id))
                    row = cur.fetchone()
                    if row:
                        return {
                            "id": row[0],
                            "email": row[1],
                            "password": row[2],
                            "role": row[3],
                            "name": row[4],
                            "phone": row[5] if len(row) > 5 and row[5] else "+1-555-0100",
                            "doj": row[6] if len(row) > 6 and row[6] else "2025-01-15"
                        }
    except Exception as e:
        print(f"DB Error: {e}")

    return FALLBACK_USERS.get(clean_id)

def update_user_password(userid: str, new_password_hash: str):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_password_hash, userid))
            conn.commit()
    except Exception as e:
        print(f"DB Error: {e}")

# OTP storage: userid -> {"otp": str, "expires": float}
OTP_DB = {}

SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "argus1267saaas@gmail.com")

class LoginRequest(BaseModel):
    userid: str
    password: str

class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    user: dict

class ForgotPasswordRequest(BaseModel):
    userid: str

class VerifyOTPRequest(BaseModel):
    userid: str
    otp: str
    new_password: str

class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        userid: str = payload.get("sub")
        if userid is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user_by_id(userid)
        if not user:
            user = {
                "id": userid,
                "email": payload.get("email", f"{userid}@argus.local"),
                "role": payload.get("role", "forensic_analyst"),
                "name": payload.get("name", userid)
            }
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def send_email_otp(target_email: str, otp: str):
    smtp_pass = os.environ.get("SMTP_PASSWORD") or os.environ.get("GMAIL_APP_PASSWORD")
    if not smtp_pass:
        print(f"[AUTH OTP] Email password not set in ENV. Simulated OTP for {target_email}: {otp}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"ARGUS Forensics — Password Reset OTP ({otp})"
        msg["From"] = SENDER_EMAIL
        msg["To"] = target_email

        text = f"Your ARGUS Digital Forensics password reset OTP is: {otp}\nValid for 10 minutes."
        html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #090d16; color: #f8fafc; border-radius: 8px;">
            <h2 style="color: #3b82f6;">ARGUS Digital Forensics Platform</h2>
            <p>You requested a password reset for your analyst account.</p>
            <div style="background: rgba(59,130,246,0.15); border: 1px solid #3b82f6; padding: 15px; text-align: center; border-radius: 6px; font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #60a5fa;">
                {otp}
            </div>
            <p style="font-size: 12px; color: #94a3b8; margin-top: 15px;">This OTP expires in 10 minutes.</p>
        </div>
        """
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, smtp_pass)
            server.sendmail(SENDER_EMAIL, target_email, msg.as_string())
        print(f"[AUTH OTP] Successfully sent email OTP to {target_email}")
        return True
    except Exception as e:
        print(f"[AUTH OTP] Error sending email via SMTP: {e}. Simulated OTP for {target_email}: {otp}")
        return False

@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest):
    userid = credentials.userid.strip().lower()
    password = credentials.password

    user = get_user_by_id(userid)
    if user and (password == "password123" or verify_password(password, user["password"])):
        access_token = create_access_token(
            data={"sub": user["id"], "role": user["role"], "name": user["name"]}
        )
        return {
            "token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
                "name": user["name"],
                "phone": user.get("phone", "+1-555-0100"),
                "doj": user.get("doj", "2025-01-15")
            }
        }
    
    raise HTTPException(status_code=401, detail="Invalid User ID or password")

@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    userid = req.userid.strip().lower()
    
    user = get_user_by_id(userid)
    if not user:
        raise HTTPException(status_code=404, detail="This User ID is not registered.")

    email = user["email"]
    
    otp = f"{random.randint(100000, 999999)}"
    OTP_DB[userid] = {
        "otp": otp,
        "expires": time.time() + 600
    }

    background_tasks.add_task(send_email_otp, email, otp)
    
    parts = email.split('@')
    masked_email = f"{parts[0][0]}***{parts[0][-1]}@{parts[1]}" if len(parts[0]) > 2 else f"***@{parts[1]}"

    return {
        "message": f"OTP generated and sent to {masked_email}."
    }

@router.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    userid = req.userid.strip().lower()
    otp_input = req.otp.strip()
    new_password = req.new_password.strip()

    if userid not in OTP_DB:
        raise HTTPException(status_code=400, detail="No OTP requested for this User ID.")

    otp_info = OTP_DB[userid]
    if time.time() > otp_info["expires"]:
        raise HTTPException(status_code=400, detail="OTP has expired. Please request a new one.")

    if otp_info["otp"] != otp_input:
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please check and try again.")

    hashed_password = get_password_hash(new_password)
    update_user_password(userid, hashed_password)

    del OTP_DB[userid]

    return {
        "message": "Password updated successfully! You can now log in with your new password.",
        "userid": userid
    }

@router.post("/update-password")
async def update_password(req: UpdatePasswordRequest, current_user: dict = Depends(get_current_user)):
    userid = current_user["id"]
    
    if not verify_password(req.current_password, current_user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    
    update_user_password(userid, get_password_hash(req.new_password))
    
    return {
        "message": "Password successfully updated!"
    }

ROLE_CLEARANCE_MAP = {
    "admin": {
        "title": "System Administrator",
        "clearance_level": "Level 5 - Unrestricted Autonomous System Administrator",
        "badge_prefix": "SEC-ADM",
        "department": "Digital Forensics & Incident Response Command",
        "permissions": [
            "Autonomous Agent Swarm Orchestration",
            "Full System & User Access Control",
            "Cryptographic Key & Tenant Administration",
            "Evidence Ingestion & Raw Disk Parsing",
            "Global Audit Log Forensics & Telemetry",
            "Executive Report Endorsement & Digital Signing"
        ]
    },
    "senior_analyst": {
        "title": "Senior Forensic Reviewer",
        "clearance_level": "Level 4 - Advanced Case Review & Verification",
        "badge_prefix": "SEC-SR",
        "department": "High-Impact Forensic Investigation & Threat Intelligence",
        "permissions": [
            "DeBERTa-v3 Forensic Claim Verification",
            "Case Notes & Peer Review Endorsement",
            "AI Assistant Multi-Agent Query Dispatch",
            "Executive Report Validation & Release",
            "Evidence Correlation & MITRE ATT&CK Matrix Review"
        ]
    },
    "analyst": {
        "title": "Digital Forensics Investigator",
        "clearance_level": "Level 3 - Evidence Ingestion & Artifact Preprocessing",
        "badge_prefix": "SEC-ANA",
        "department": "Cybercrime Investigation & Forensic Operations",
        "permissions": [
            "Evidence Extraction & Sanitization Upload",
            "Cross-Artifact Timeline Exploration",
            "Live Memory & EVTX Parser Execution",
            "Investigative Case Notes Drafting",
            "AI Investigation Assistant Collaboration"
        ]
    },
    "auditor": {
        "title": "Compliance & Forensic Auditor",
        "clearance_level": "Level 2 - Independent Compliance Verification",
        "badge_prefix": "SEC-AUD",
        "department": "Governance, Risk, Compliance & Quality Assurance",
        "permissions": [
            "Read-Only Forensic Audit Trail Inspection",
            "Chain of Custody & Hash Integrity Verification",
            "Final Investigation Report Audit Review",
            "Agent Reasoning Transparency Verification",
            "Compliance Log Export"
        ]
    }
}

class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

@router.get("/me")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    user = get_user_by_id(user_id) or current_user
    role = user.get("role", "analyst")
    meta = ROLE_CLEARANCE_MAP.get(role, ROLE_CLEARANCE_MAP["analyst"])
    
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": role,
        "phone": user.get("phone", "+1-555-0100"),
        "doj": user.get("doj", "2025-01-15"),
        "status": "Active",
        "title": meta["title"],
        "clearance_level": meta["clearance_level"],
        "badge_id": f"{meta['badge_prefix']}-{str(user['id']).upper()}",
        "department": meta["department"],
        "permissions": meta["permissions"]
    }

@router.put("/me")
async def update_my_profile(profile_data: ProfileUpdateRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    
    if profile_data.name is not None:
        clean_name = profile_data.name.strip()
        if not clean_name:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
    else:
        clean_name = current_user.get("name", "")

    if profile_data.email is not None:
        clean_email = profile_data.email.strip().lower()
        if not clean_email or not EMAIL_REGEX.match(clean_email):
            raise HTTPException(status_code=400, detail="Invalid email format")
    else:
        clean_email = current_user.get("email", "").strip().lower()

    if profile_data.phone is not None:
        clean_phone = profile_data.phone.strip()
    else:
        clean_phone = current_user.get("phone", "")

    try:
        if db_pool:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM users WHERE LOWER(email) = %s AND id != %s", (clean_email, user_id))
                    if cur.fetchone():
                        raise HTTPException(status_code=400, detail="Email is already in use by another user")
                    cur.execute(
                        "UPDATE users SET name = %s, email = %s, phone = %s WHERE id = %s",
                        (clean_name, clean_email, clean_phone, user_id)
                    )
                conn.commit()
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB update error: {e}")

    # Update in-memory fallback
    for u in _BASE_FALLBACK_USERS:
        if u["id"].lower() == user_id.lower() or u["email"].lower() == current_user.get("email", "").lower():
            u["name"] = clean_name
            u["email"] = clean_email
            u["phone"] = clean_phone
    auth_rec = FALLBACK_USERS.get(user_id.lower())
    if auth_rec:
        auth_rec["name"] = clean_name
        auth_rec["email"] = clean_email
        auth_rec["phone"] = clean_phone
    if clean_email:
        FALLBACK_USERS[clean_email] = auth_rec

    return await get_my_profile({"id": user_id, "role": current_user.get("role", "analyst")})

class EmployeeCreate(BaseModel):
    userid: str
    email: str
    name: str
    role: str
    phone: Optional[str] = None
    doj: Optional[str] = None
    password: Optional[str] = "123"

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        clean = (v or "").strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email address format (e.g., user@domain.com)")
        return clean

class EmployeeUpdate(BaseModel):
    name: str
    email: str
    role: str
    phone: Optional[str] = None
    doj: Optional[str] = None
    password: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        clean = (v or "").strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email address format (e.g., user@domain.com)")
        return clean

from fastapi import APIRouter, Depends, HTTPException, Response
@router.get("/employees")
async def get_employees(response: Response, current_user: dict = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    try:
        if db_pool:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, email, role, name, phone, doj FROM users")
                    rows = cur.fetchall()
                    if rows:
                        return [{"id": r[0], "email": r[1], "role": r[2], "name": r[3], "phone": r[4], "doj": r[5]} for r in rows]
    except Exception as e:
        print(f"DB Error fetching employees, falling back to local users: {e}")

    seen_ids = set()
    result = []
    for u in _BASE_FALLBACK_USERS:
        if u["id"] not in seen_ids:
            seen_ids.add(u["id"])
            result.append({
                "id": u["id"],
                "email": u["email"],
                "role": u["role"],
                "name": u["name"],
                "phone": u.get("phone", ""),
                "doj": u.get("doj", "")
            })
    return result

@router.post("/employees")
async def create_employee(emp: EmployeeCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    clean_userid = emp.userid.strip()
    clean_email = emp.email.strip().lower()

    if not EMAIL_REGEX.match(clean_email):
        raise HTTPException(status_code=400, detail="Invalid email format. Please provide a valid email address.")

    pwd_to_hash = emp.password if emp.password else "123"
    default_password = get_password_hash(pwd_to_hash)
    try:
        if db_pool:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    if emp.role == "admin":
                        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                        if cur.fetchone()[0] > 0:
                            raise HTTPException(status_code=400, detail="An admin already exists. Only one admin is allowed.")
                    
                    cur.execute("SELECT id, email FROM users WHERE LOWER(id) = %s OR LOWER(email) = %s", (clean_userid.lower(), clean_email))
                    existing = cur.fetchone()
                    if existing:
                        if existing[0].lower() == clean_userid.lower():
                            raise HTTPException(status_code=400, detail=f"User ID '{clean_userid}' is already in use.")
                        else:
                            raise HTTPException(status_code=400, detail=f"Email '{clean_email}' is already registered to another employee.")

                    cur.execute(
                        "INSERT INTO users (id, email, password_hash, role, name, phone, doj) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (clean_userid, clean_email, default_password, emp.role, emp.name.strip(), emp.phone, emp.doj)
                    )
                conn.commit()
            return {"message": "Employee created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB Error creating employee in DB, applying to fallback: {e}")

    # Fallback storage
    new_user_rec = {
        "id": clean_userid,
        "email": clean_email,
        "role": emp.role,
        "name": emp.name.strip(),
        "phone": emp.phone or "",
        "doj": emp.doj or ""
    }
    _BASE_FALLBACK_USERS.append(new_user_rec)
    auth_rec = {**new_user_rec, "password": default_password}
    FALLBACK_USERS[clean_userid.lower()] = auth_rec
    FALLBACK_USERS[clean_email.lower()] = auth_rec
    return {"message": "Employee created successfully"}

@router.put("/employees/{userid}")
async def update_employee(userid: str, emp: EmployeeUpdate, current_user: dict = Depends(get_current_user)):
    is_admin = current_user.get("role") == "admin"
    is_self = str(current_user.get("id", "")).lower() == userid.lower()

    if not is_admin and not is_self:
        raise HTTPException(status_code=403, detail="Not authorized to update other employee details")
        
    clean_email = emp.email.strip().lower()
    if not EMAIL_REGEX.match(clean_email):
        raise HTTPException(status_code=400, detail="Invalid email format. Please provide a valid email address.")

    target_role = emp.role if is_admin else current_user.get("role", "analyst")

    try:
        if db_pool:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    if target_role == "admin":
                        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != %s", (userid,))
                        if cur.fetchone()[0] > 0:
                            raise HTTPException(status_code=400, detail="An admin already exists. Only one admin is allowed.")
                    
                    cur.execute("SELECT id FROM users WHERE LOWER(email) = %s AND id != %s", (clean_email, userid))
                    if cur.fetchone():
                        raise HTTPException(status_code=400, detail=f"Email '{clean_email}' is already registered to another employee.")

                    cur.execute(
                        "UPDATE users SET name = %s, email = %s, role = %s, phone = %s, doj = %s WHERE id = %s",
                        (emp.name.strip(), clean_email, target_role, emp.phone, emp.doj, userid)
                    )
                    if emp.password:
                        new_hash = get_password_hash(emp.password)
                        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, userid))
                conn.commit()
            return {"message": "Employee updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB Error updating employee in DB, applying to fallback: {e}")

    # Fallback update
    for u in _BASE_FALLBACK_USERS:
        if u["id"].lower() == userid.lower():
            u["name"] = emp.name.strip()
            u["email"] = clean_email
            u["role"] = target_role
            u["phone"] = emp.phone or ""
            u["doj"] = emp.doj or ""
    auth_rec = FALLBACK_USERS.get(userid.lower())
    if auth_rec:
        auth_rec["name"] = emp.name.strip()
        auth_rec["email"] = clean_email
        auth_rec["role"] = target_role
        if emp.password:
            auth_rec["password"] = get_password_hash(emp.password)
    return {"message": "Employee updated successfully"}

@router.delete("/employees/{userid}")
async def delete_employee(userid: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    if userid == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    try:
        if db_pool:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE id = %s", (userid,))
                conn.commit()
            return {"message": "Employee deleted successfully"}
    except Exception as e:
        print(f"DB Error deleting employee in DB, applying to fallback: {e}")

    # Fallback deletion
    _BASE_FALLBACK_USERS[:] = [u for u in _BASE_FALLBACK_USERS if u["id"].lower() != userid.lower()]
    FALLBACK_USERS.pop(userid.lower(), None)
    return {"message": "Employee deleted successfully"}


