from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Boolean, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

app = FastAPI()

DATABASE_URL = "sqlite:///./hospital.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    role = Column(String)  # 'admin' or 'patient'

class MedicationReminder(Base):
    __tablename__ = "medications"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String)
    time = Column(String)
    completed = Column(Boolean, default=False)
    
class Todo(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    task = Column(String)
    completed = Column(Boolean, default=False)

class Caregiver(Base):
    __tablename__ = "caregivers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    specialization = Column(String)
    available = Column(Boolean, default=True)

class HireRequest(Base):
    __tablename__ = "hire_requests"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    caregiver_id = Column(Integer, ForeignKey("caregivers.id"))
    status = Column(String, default="Pending")

class MedicalRecord(Base):
    __tablename__ = "medical_records"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    record = Column(String)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/users/")
def create_user(name: str, role: str, db: Session = Depends(get_db)):
    user = User(name=name, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/medications/")
def add_medication(patient_id: int, name: str, time: str, db: Session = Depends(get_db)):
    medication = MedicationReminder(patient_id=patient_id, name=name, time=time)
    db.add(medication)
    db.commit()
    return {"message": "Medication added"}

@app.post("/todos/")
def add_todo(patient_id: int, task: str, db: Session = Depends(get_db)):
    todo = Todo(patient_id=patient_id, task=task)
    db.add(todo)
    db.commit()
    return {"message": "To-do added"}

@app.post("/caregivers/")
def add_caregiver(name: str, specialization: str, db: Session = Depends(get_db)):
    caregiver = Caregiver(name=name, specialization=specialization)
    db.add(caregiver)
    db.commit()
    return {"message": "Caregiver added"}

@app.post("/hire/")
def hire_caregiver(patient_id: int, caregiver_id: int, db: Session = Depends(get_db)):
    hire_request = HireRequest(patient_id=patient_id, caregiver_id=caregiver_id)
    db.add(hire_request)
    db.commit()
    return {"message": "Caregiver hired"}

@app.get("/dashboard/admin/")
def get_admin_dashboard(db: Session = Depends(get_db)):
    caregivers = db.query(Caregiver).all()
    patients = db.query(User).filter(User.role == "patient").all()
    hire_requests = db.query(HireRequest).all()
    return {"caregivers": caregivers, "patients": patients, "hire_requests": hire_requests}
