from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
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
from dotenv import load_dotenv
load_dotenv()

router = APIRouter()

SECRET_KEY = "argus_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

import psycopg2

from contextlib import contextmanager

@contextmanager
def get_db_connection():
    conn = psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5433"),
        database=os.environ.get("POSTGRES_DB", "argus"),
        user=os.environ.get("POSTGRES_USER", "argus_user"),
        password=os.environ.get("POSTGRES_PASSWORD", "argus_dev")
    )
    try:
        yield conn
    finally:
        conn.close()

def get_user_by_id(userid: str):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, password_hash, role, name FROM users WHERE id = %s", (userid,))
                row = cur.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "email": row[1],
                        "password": row[2],
                        "role": row[3],
                        "name": row[4]
                    }
    except Exception as e:
        print(f"DB Error: {e}")
    return None

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
            raise HTTPException(status_code=401, detail="Invalid token")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
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
    if user and verify_password(password, user["password"]):
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
                "name": user["name"]
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

class EmployeeCreate(BaseModel):
    userid: str
    email: str
    name: str
    role: str
    phone: Optional[str] = None
    doj: Optional[str] = None
    password: Optional[str] = "1"

class EmployeeUpdate(BaseModel):
    name: str
    email: str
    role: str
    phone: Optional[str] = None
    doj: Optional[str] = None
    password: Optional[str] = None

@router.get("/employees")
async def get_employees(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, role, name, phone, doj FROM users")
                rows = cur.fetchall()
                return [{"id": r[0], "email": r[1], "role": r[2], "name": r[3], "phone": r[4], "doj": r[5]} for r in rows]
    except Exception as e:
        print(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@router.post("/employees")
async def create_employee(emp: EmployeeCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    pwd_to_hash = emp.password if emp.password else "1"
    default_password = get_password_hash(pwd_to_hash)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                if emp.role == "admin":
                    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                    if cur.fetchone()[0] > 0:
                        raise HTTPException(status_code=400, detail="An admin already exists. Only one admin is allowed.")
                
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, role, name, phone, doj) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (emp.userid, emp.email, default_password, emp.role, emp.name, emp.phone, emp.doj)
                )
            conn.commit()
        return {"message": "Employee created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database error or user already exists")

@router.put("/employees/{userid}")
async def update_employee(userid: str, emp: EmployeeUpdate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
        
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                if emp.role == "admin":
                    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != %s", (userid,))
                    if cur.fetchone()[0] > 0:
                        raise HTTPException(status_code=400, detail="An admin already exists. Only one admin is allowed.")
                
                cur.execute(
                    "UPDATE users SET name = %s, email = %s, role = %s, phone = %s, doj = %s WHERE id = %s",
                    (emp.name, emp.email, emp.role, emp.phone, emp.doj, userid)
                )
                # Update password if a new one was provided
                if emp.password:
                    new_hash = get_password_hash(emp.password)
                    cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, userid))
            conn.commit()
        return {"message": "Employee updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@router.delete("/employees/{userid}")
async def delete_employee(userid: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    if userid == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (userid,))
            conn.commit()
        return {"message": "Employee deleted successfully"}
    except Exception as e:
        print(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

