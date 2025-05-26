from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    plan: str
    chart_count: int
    appeal_count: int
    last_reset: str

    class Config:
        orm_mode = True