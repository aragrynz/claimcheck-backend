from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from dotenv import load_dotenv
from typing import Optional, Union
from sqlalchemy.orm import Session
import models, schemas, database
from database import engine
from auth import get_password_hash, authenticate_user, create_access_token, get_current_user
import openai
import os

# Load environment variables and set OpenAI key
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# Init FastAPI app
app = FastAPI()

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create the database tables
models.Base.metadata.create_all(bind=engine)

# Root
@app.get("/")
def read_root():
    return {"message": "ClaimCheck AI backend is running!"}

@app.get("/apikey")
def get_key():
    return {"api_key": os.getenv("OPENAI_API_KEY")}

# --------------------
# 🔐 AUTH ROUTES
# --------------------

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# --------------------
# ✅ STEP 2 – /process-chart
# --------------------
@app.post("/process-chart")
async def process_chart(
    file: Union[UploadFile, None] = File(default=None),
    chart_text: Optional[str] = Form(default=None),
    current_user: schemas.UserOut = Depends(get_current_user)
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
                        "and the correct CMS guidelines for the year of service. Also, identify when modifiers (e.g., -25, -59) are required "
                        "and explain why."
                    ),
                },
                {"role": "user", "content": text_data}
            ]
        )

        reply = response.choices[0].message.content
        return {"coding_result": reply}

    except Exception as e:
        print("ERROR:", str(e))
        return JSONResponse(status_code=500, content={"error": str(e)})

# --------------------
# ✅ STEP 3 – /generate-appeal
# --------------------
@app.post("/generate-appeal")
async def generate_appeal(
    file: Union[UploadFile, None] = File(default=None),
    denial_text: Optional[str] = Form(default=None),
    current_user: schemas.UserOut = Depends(get_current_user)
):
    try:
        if file and file.filename:
            content = await file.read()
            input_text = content.decode(errors="ignore")[:4000]
        elif denial_text:
            input_text = denial_text[:4000]
        else:
            return JSONResponse(status_code=400, content={"error": "Please upload a file or paste denial information."})

        prompt = (
            "You are a medical billing and appeals specialist. Based on the denial or EOB information below, "
            "generate a professional appeal letter for the healthcare provider. Reference the correct CPT code(s), "
            "justify medical necessity, and cite CMS or payer guidelines when relevant. Make the appeal suitable for submission to the insurance company.\n\n"
            f"{input_text}"
        )

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": prompt}]
        )

        appeal_text = response.choices[0].message.content
        return {"appeal_letter": appeal_text}

    except Exception as e:
        print("ERROR:", str(e))
        return JSONResponse(status_code=500, content={"error": str(e)})