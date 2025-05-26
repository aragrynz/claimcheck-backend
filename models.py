from sqlalchemy import Column, Integer, String
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    plan = Column(String, default="Free")  # Free, Starter, Pro, Enterprise
    chart_count = Column(Integer, default=0)
    appeal_count = Column(Integer, default=0)
    last_reset = Column(String, default="")