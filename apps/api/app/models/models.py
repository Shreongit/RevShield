import uuid
from datetime import datetime, timezone
from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    reports = relationship("AnalysisReport", back_populates="user", cascade="all, delete-orphan")
    whitelist_items = relationship("WhitelistItem", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("ExtensionDevice", back_populates="user", cascade="all, delete-orphan")
    saved_reports = relationship("SavedReport", back_populates="user", cascade="all, delete-orphan")

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), index=True, nullable=False)
    target_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    overall_score = Column(Integer, nullable=False)
    security_score = Column(Integer, nullable=False)
    privacy_score = Column(Integer, nullable=False)
    threat_score = Column(Integer, nullable=False)
    risk_classification = Column(String(32), nullable=False)
    execution_time_ms = Column(Integer, default=0)
    report_json = Column(JSON, nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)

    user = relationship("User", back_populates="reports")
    saved_by = relationship("SavedReport", back_populates="report", cascade="all, delete-orphan")

class WhitelistItem(Base):
    __tablename__ = "whitelist_items"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    reason = Column(String(255), default="User whitelisted")
    created_at = Column(DateTime(timezone=True), default=utc_now)

    user = relationship("User", back_populates="whitelist_items")

class ExtensionDevice(Base):
    __tablename__ = "extension_devices"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_name = Column(String(128), default="Browser Extension")
    browser = Column(String(64), default="Chrome")
    extension_version = Column(String(32), default="1.0.0")
    total_ads_blocked = Column(Integer, default=0)
    total_trackers_blocked = Column(Integer, default=0)
    last_synced_at = Column(DateTime(timezone=True), default=utc_now)

    user = relationship("User", back_populates="devices")

class SavedReport(Base):
    __tablename__ = "saved_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    report_id = Column(String(36), ForeignKey("analysis_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    user = relationship("User", back_populates="saved_reports")
    report = relationship("AnalysisReport", back_populates="saved_by")
