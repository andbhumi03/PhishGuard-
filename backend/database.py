from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./phishguard.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String)  # "paste" or "eml"
    sender_name = Column(String)
    sender_email = Column(String)
    subject = Column(String)
    body = Column(Text)
    risk_score = Column(Float)
    risk_level = Column(String)
    ml_prediction = Column(String)
    ml_confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

    urls = relationship("URLRecord", back_populates="analysis")
    reasons = relationship("ReasonRecord", back_populates="analysis")


class URLRecord(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"))
    url = Column(String)
    domain = Column(String)
    uses_https = Column(String)
    is_suspicious = Column(String)

    analysis = relationship("Analysis", back_populates="urls")


class ReasonRecord(Base):
    __tablename__ = "reasons"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"))
    message = Column(Text)

    analysis = relationship("Analysis", back_populates="reasons")


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()