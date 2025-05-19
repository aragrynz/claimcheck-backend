from fastapi import FastAPI, UploadFile, File, Form, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from typing import Optional, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from pydantic import BaseModel
import openai
import stripe
import os

# Load environment variables
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe_webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

# FastAPI app
app = FastAPI()

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# In-memory user store (replace with DB in production)
fake_users_db = {}

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return True

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register")
def register(user: User):
    if user.username in fake_users_db:
        return {"error": "User already exists"}
    hashed = get_password_hash(user.password)
    fake_users_db[user.username] = {"hashed_password": hashed}
    return {"message": "User registered successfully"}

@app.post("/token", response_model=Token)
def login(user: User):
    if not authenticate_user(user.username, user.password):
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"message": "ClaimCheck AI backend is running!"}

@app.get("/apikey")
def get_key():
    return {"api_key": os.getenv("OPENAI_API_KEY")}

@app.post("/process-chart")
async def process_chart(
    file: Union[UploadFile, None] = File(default=None),
    chart_text: Optional[str] = Form(default=None)
):
    try:
        if file and file.filename:
            content = await file.read()
            text_data = content.decode(errors="ignore")[:4000]
        elif chart_text:
            text_data = chart_text[:4000]
        else:
            return JSONResponse(status_code=400, content={"error": "Please upload a file or provide chart text."})

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a certified medical coder. Determine CPT, ICD-10, and HCPCS codes based on the clinical documentation "
                        "and the correct CMS guidelines for the date of service. Identify when modifiers like -25 are required and why."
                    ),
                },
                {"role": "user", "content": text_data}
            ]
        )

        reply = response.choices[0].message.content
        return {"coding_result": reply.strip()}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/generate-appeal")
async def generate_appeal(
    file: Union[UploadFile, None] = File(default=None),
    denial_text: Optional[str] = Form(default=None)
):
    try:
        if file and file.filename:
            content = await file.read()
            text_data = content.decode(errors="ignore")[:4000]
        elif denial_text:
            text_data = denial_text[:4000]
        else:
            return JSONResponse(status_code=400, content={"error": "Please upload a file or paste denial text."})

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a medical claim appeals specialist. Write a professional and concise letter explaining why the claim "
                        "should be reconsidered and reimbursed. Include medical necessity, coding logic, and CMS guidance."
                    ),
                },
                {"role": "user", "content": text_data}
            ]
        )

        appeal_letter = response.choices[0].message.content
        return {"appeal_letter": appeal_letter.strip()}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid payload"})
    except stripe.error.SignatureVerificationError:
        return JSONResponse(status_code=400, content={"error": "Invalid signature"})

    event_type = event['type']
    data = event['data']['object']

    if event_type == 'checkout.session.completed':
        customer_email = data.get("customer_email")
        print(f"✅ Payment completed for {customer_email}")
        # TODO: Mark user as paid

    elif event_type == 'invoice.payment_succeeded':
        print("💰 Payment succeeded")

    elif event_type == 'invoice.payment_failed':
        print("❌ Payment failed")

    elif event_type == 'customer.subscription.deleted':
        print("🔻 Subscription canceled")

    elif event_type == 'customer.subscription.updated':
        print("🔄 Subscription updated")

    return JSONResponse(status_code=200, content={"status": "success"})