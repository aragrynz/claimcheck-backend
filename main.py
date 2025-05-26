# main.py (fully expanded and corrected version)
from fastapi import FastAPI, UploadFile, File, Form, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session as BackgroundSession, Session
from datetime import datetime
from dotenv import load_dotenv
from typing import Optional, Union
import openai
import stripe
import os

# TEMP: Delete existing SQLite DB to force schema refresh
if os.path.exists("users.db"):
    os.remove("users.db")
    print("🗑️ users.db deleted – will regenerate from models.py")
    
import models, schemas, database
from auth import get_password_hash, authenticate_user, create_access_token, get_current_user

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)

# === Monthly Reset Job ===
def reset_usage_counts():
    db: BackgroundSession = next(database.get_db())
    now = datetime.utcnow().strftime("%Y-%m")
    users = db.query(models.User).all()
    for user in users:
        user.chart_count = 0
        user.appeal_count = 0
        user.last_reset = now
    db.commit()
    db.close()
    print("✅ Monthly usage counts reset.")

scheduler = BackgroundScheduler()
scheduler.add_job(reset_usage_counts, trigger="cron", day=1, hour=0)
scheduler.start()

# === HTML Routes ===
@app.get("/", response_class=HTMLResponse)
def homepage():
    return load_html("index.html")

@app.get("/pricing", response_class=HTMLResponse)
def serve_pricing():
    return load_html("pricing.html")

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return load_html("login.html")

@app.get("/register", response_class=HTMLResponse)
def register_page():
    print("✅ GET /register route was triggered")
    return load_html("register.html")

@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(database.get_db)
):
    if db.query(models.User).filter(models.User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(password)
    db_user = models.User(username=username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return load_html("dashboard.html")

@app.get("/chart-upload", response_class=HTMLResponse)
def chart_upload():
    return load_html("chart_upload.html")

@app.get("/admin", response_class=HTMLResponse)
def admin_page(current_user=Depends(get_current_user)):
    if current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return load_html("admin.html")

@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    return load_html("terms.html")

# === API Routes ===
@app.get("/apikey")
def get_key():
    return {"api_key": os.getenv("OPENAI_API_KEY")}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        return JSONResponse(status_code=400, content={"error": "Invalid credentials"})
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/account")
def get_account_info(current_user: models.User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "plan": current_user.plan,
        "chart_count": current_user.chart_count,
        "appeal_count": current_user.appeal_count,
        "last_reset": current_user.last_reset
    }

@app.get("/admin/users")
def get_all_users(current_user=Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    users = db.query(models.User).all()
    return [
        {
            "username": u.username,
            "plan": u.plan,
            "chart_count": u.chart_count,
            "appeal_count": u.appeal_count,
            "last_reset": u.last_reset
        } for u in users
    ]

@app.post("/process-chart")
async def process_chart(
    file: Union[UploadFile, None] = File(default=None),
    chart_text: Optional[str] = Form(default=None),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.chart_count >= 3 and current_user.plan == "Free":
        return JSONResponse(status_code=403, content={"error": "Free plan chart limit reached"})

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
                {"role": "system", "content": "You are a certified medical coder. Determine CPT, ICD-10, and HCPCS codes."},
                {"role": "user", "content": text_data}
            ]
        )
        reply = response.choices[0].message.content
        current_user.chart_count += 1
        db.commit()
        return {"coding_result": reply}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/generate-appeal")
async def generate_appeal(
    file: Union[UploadFile, None] = File(default=None),
    denial_text: Optional[str] = Form(default=None),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.appeal_count >= 3 and current_user.plan == "Free":
        return JSONResponse(status_code=403, content={"error": "Free plan appeal limit reached"})

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
                {"role": "system", "content": "You are a healthcare appeal writer. Draft a dispute letter."},
                {"role": "user", "content": text_data}
            ]
        )
        reply = response.choices[0].message.content
        current_user.appeal_count += 1
        db.commit()
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
        session = stripe.checkout.Session.create(
            success_url="https://claimcheck.online/dashboard",
            cancel_url="https://claimcheck.online/pricing",
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}]
        )
        return {"url": session.url}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(database.get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except stripe.error.SignatureVerificationError:
        return JSONResponse(status_code=400, content={"error": "Invalid signature"})

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_email")
        price_id = session.get("display_items", [{}])[0].get("price", {}).get("id")
        plan_lookup = {
            os.getenv("STARTER_PRICE_ID"): "Starter",
            os.getenv("PRO_PRICE_ID"): "Pro",
            os.getenv("ENTERPRISE_PRICE_ID"): "Enterprise"
        }
        plan = plan_lookup.get(price_id, "Free")
        user = db.query(models.User).filter(models.User.username == email).first()
        if user:
            user.plan = plan
            db.commit()

    elif event["type"] == "invoice.payment_failed":
        session = event["data"]["object"]
        email = session.get("customer_email")
        user = db.query(models.User).filter(models.User.username == email).first()
        if user:
            user.plan = "Free"
            db.commit()

    return {"status": "success"}

# Utility to load HTML
def load_html(filename):
    try:
        base_dir = os.path.dirname(__file__)
        path = os.path.join(base_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        return HTMLResponse(content=f"<h1>Error loading {filename}: {e}</h1>", status_code=500)
