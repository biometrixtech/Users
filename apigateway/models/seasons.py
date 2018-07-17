from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, text
from db_connection import Base


class Season(Base):
    __tablename__ = "seasons"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False, server_default=text("now()"))
    start_month = Column(String)
    end_month = Column(String)
