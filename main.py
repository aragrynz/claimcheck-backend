from fastapi import FastAPI, UploadFile, File, Form, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from dotenv import load_dotenv
from typing import Optional, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import openai
import stripe
import os

import models, schemas, database
from auth import get_password_hash, authenticate_user, create_access_token, get_current_user

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)

@app.get("/")
def read_root():
    return {"message": "ClaimCheck AI backend is running!"}

@app.get("/apikey")
def get_key():
    return {"api_key": os.getenv("OPENAI_API_KEY")}

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        return JSONResponse(status_code=400, content={"error": "Invalid credentials"})
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

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
                        "You are a certified medical coder. Determine CPT, ICD-10, and HCPCS codes based on the clinical documentation and the correct CMS guidelines for the year of service. Also, identify when modifiers (e.g., -25, -59) are required and explain why."
                    ),
                },
                {"role": "user", "content": text_data}
            ]
        )
        reply = response.choices[0].message.content
        return {"coding_result": reply}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/analyze-eob")
async def analyze_eob(file: UploadFile = File(...), contract_percent: float = Form(...)):
    content = await file.read()
    text_data = content.decode(errors="ignore")[:4000]

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a medical reimbursement analyst. Analyze EOBs and compare payment vs contract."},
            {"role": "user", "content": f"EOB text:\n{text_data}\n\nContract: {contract_percent}% of Medicare. Identify any under/overpayments or denial issues."}
        ]
    )
    reply = response.choices[0].message.content
    return {"eob_analysis": reply}

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
            return JSONResponse(status_code=400, content={"error": "Please upload a file or provide appeal text."})

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a healthcare appeal writer. Draft a rational, well-supported letter to dispute a denied or underpaid claim."},
                {"role": "user", "content": text_data}
            ]
        )
        reply = response.choices[0].message.content
        return {"appeal_letter": reply}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/create-checkout-session")
async def create_checkout_session(request: Request):
    form = await request.form()
    price_id = form.get("price_id")

    if not price_id:
        return JSONResponse(status_code=400, content={"error": "Missing price ID"})

    try:
        checkout_session = stripe.checkout.Session.create(
            success_url="https://claimcheck.online/dashboard",
            cancel_url="https://claimcheck.online/pricing",
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{
                "price": price_id,
                "quantity": 1
            }]
        )
        return JSONResponse({"url": checkout_session.url})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
