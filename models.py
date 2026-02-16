from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True, index=True) # e.g., 'num', 'adh'
    source_url_template = Column(Text)
    description = Column(String, nullable=True)
    keys = relationship("ApiKey", back_populates="endpoint", cascade="all, delete-orphan")

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expiry_date = Column(DateTime, nullable=True) # None = never expires
    is_active = Column(Boolean, default=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    
    endpoint = relationship("Endpoint", back_populates="keys")

class RequestLog(Base):
    __tablename__ = "request_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    method = Column(String)
    path = Column(String)
    status_code = Column(Integer)
    client_ip = Column(String)
    latency_ms = Column(Integer)

class Settings(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True, index=True)
    admin_secret_key = Column(String, default="your-secret-key-here") # For JWT
