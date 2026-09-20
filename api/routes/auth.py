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

# In-memory user database
USERS_DB = {
    "remakhat115@gmail.com": {
        "id": "u-115",
        "email": "remakhat115@gmail.com",
        "password": "$2b$12$NQhT3fIoXDJ0OWV7RFnW2egMzA9IUcxpewsO7VBKWRtQOGscU6wWe",
        "role": "analyst",
        "name": "Remakhat"
    },
    "analyst@agency.gov": {
        "id": "u-1234",
        "email": "analyst@agency.gov",
        "password": "$2b$12$dSjWP/zDDtYMFf6N3krNaOJKnD4PdGEjoi78K5mh24c60ig7TCvkO",
        "role": "analyst",
        "name": "Senior Analyst"
    }
}

# OTP storage: email -> {"otp": str, "expires": float}
OTP_DB = {}

SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "argus1267saaas@gmail.com")

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    user: dict

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyOTPRequest(BaseModel):
    email: str
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
        email: str = payload.get("sub")
        if email is None or email not in USERS_DB:
            raise HTTPException(status_code=401, detail="Invalid token")
        return USERS_DB[email]
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
async def login(credentials: LoginRequest):
    email = credentials.email.strip().lower()
    password = credentials.password

    # Check database
    if email in USERS_DB and verify_password(password, USERS_DB[email]["password"]):
        user = USERS_DB[email]
        access_token = create_access_token(
            data={"sub": user["email"], "role": user["role"], "name": user["name"]}
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
    
    # If we got here, the credentials don't match or the user doesn't exist
    raise HTTPException(status_code=401, detail="Invalid email or password")

@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    email = req.email.strip().lower()
    
    # Ensure user exists
    if email not in USERS_DB:
        raise HTTPException(status_code=404, detail="This employee is not registered.")

    # Generate 6-digit OTP
    otp = f"{random.randint(100000, 999999)}"
    OTP_DB[email] = {
        "otp": otp,
        "expires": time.time() + 600 # 10 minutes
    }

    # Attempt background email dispatch
    background_tasks.add_task(send_email_otp, email, otp)

    return {
        "message": f"OTP generated and sent from {SENDER_EMAIL} to {email}.",
        "email": email,
        "otp": otp, # Include in response for seamless UI testing & verification
        "sender": SENDER_EMAIL
    }

@router.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    email = req.email.strip().lower()
    otp_input = req.otp.strip()
    new_password = req.new_password.strip()

    if email not in OTP_DB:
        raise HTTPException(status_code=400, detail="No OTP requested for this email.")

    otp_info = OTP_DB[email]
    if time.time() > otp_info["expires"]:
        raise HTTPException(status_code=400, detail="OTP has expired. Please request a new one.")

    if otp_info["otp"] != otp_input:
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please check and try again.")

    # Reset user password in database
    hashed_password = get_password_hash(new_password)
    if email in USERS_DB:
        USERS_DB[email]["password"] = hashed_password
    else:
        USERS_DB[email] = {
            "id": f"u-{random.randint(1000, 9999)}",
            "email": email,
            "password": hashed_password,
            "role": "analyst",
            "name": email.split('@')[0].replace('.', ' ').title()
        }

    # Clear OTP
    del OTP_DB[email]

    return {
        "message": "Password updated successfully! You can now log in with your new password.",
        "email": email
    }

@router.post("/update-password")
async def update_password(req: UpdatePasswordRequest, current_user: dict = Depends(get_current_user)):
    email = current_user["email"]
    
    if not verify_password(req.current_password, USERS_DB[email]["password"]):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    
    USERS_DB[email]["password"] = get_password_hash(req.new_password)
    
    return {
        "message": "Password successfully updated!"
    }

