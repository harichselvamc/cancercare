from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float, Boolean, create_engine
from sqlalchemy.orm import relationship, Session, declarative_base, sessionmaker
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List, Optional
import os

# --------------------
# Database configuration
# --------------------
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --------------------
# JWT & Password Setup
# --------------------
SECRET_KEY = "your_secret_key"  # CHANGE THIS FOR PRODUCTION!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Default OAuth2 scheme set to admin login endpoint; others have their own.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --------------------
# Database Models
# --------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)  # may be null for non-admin logins
    hashed_password = Column(String, nullable=True)
    age = Column(Integer)
    phone = Column(String)
    guardian_phone = Column(String, nullable=True)
    role = Column(String)  # "patient", "doctor", "caregiver", "admin"
    cancer_info = relationship("CancerInfo", back_populates="user", uselist=False)
    patient_profile = relationship("PatientProfile", back_populates="user", uselist=False)
    doctor_profile = relationship("DoctorProfile", back_populates="user", uselist=False)
    caregiver_profile = relationship("CaregiverProfile", back_populates="user", uselist=False)

class CancerInfo(Base):
    __tablename__ = "cancer_info"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    cancer_type = Column(String)
    stage = Column(String)
    treatment_plan = Column(String)
    estimated_cost = Column(Float)
    user = relationship("User", back_populates="cancer_info")

class Reminder(Base):
    __tablename__ = "reminders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String)
    description = Column(String)
    reminder_time = Column(DateTime)

class Todo(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    task = Column(String)
    completed = Column(Boolean, default=False)

class MedicalRecord(Base):
    __tablename__ = "medical_records"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String)
    description = Column(String)
    upload_time = Column(DateTime, default=datetime.utcnow)

# Many-to-many linking table for doctor–patient relationships
class DoctorPatient(Base):
    __tablename__ = "doctor_patients"
    id = Column(Integer, primary_key=True, index=True)
    doctor_id = Column(Integer, ForeignKey("users.id"))
    patient_id = Column(Integer, ForeignKey("users.id"))

# Profile tables for additional details
class PatientProfile(Base):
    __tablename__ = "patient_profiles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    blood_group = Column(String)
    native_place = Column(String)
    height = Column(Float)
    weight = Column(Float)
    disease_name = Column(String)
    disease_stage = Column(String)
    caretaker = Column(Boolean)
    allergy_details = Column(String)
    user = relationship("User", back_populates="patient_profile")

class DoctorProfile(Base):
    __tablename__ = "doctor_profiles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    experience = Column(Integer)
    domain = Column(String)
    available_time = Column(String)
    place = Column(String)
    price_per_consulting = Column(Float)
    user = relationship("User", back_populates="doctor_profile")

class CaregiverProfile(Base):
    __tablename__ = "caregiver_profiles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    blood_group = Column(String)
    place = Column(String)
    experience = Column(Integer)
    price_per_day = Column(Float)
    user = relationship("User", back_populates="caregiver_profile")

# --------------------
# Pydantic Schemas
# --------------------
class UserOut(BaseModel):
    id: int
    name: str
    email: Optional[EmailStr] = None
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    role: str
    class Config:
         from_attributes = True


# Schemas for profile creation (admin endpoints)
class PatientProfileCreate(BaseModel):
    blood_group: str
    native_place: str
    height: float
    weight: float
    disease_name: str
    disease_stage: str
    caretaker: bool
    allergy_details: str

class DoctorProfileCreate(BaseModel):
    experience: int
    domain: str
    available_time: str
    place: str
    price_per_consulting: float

class CaregiverProfileCreate(BaseModel):
    blood_group: str
    place: str
    experience: int
    price_per_day: float

# Combined creation schemas for admin
class PatientCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    profile: PatientProfileCreate

class DoctorCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    profile: DoctorProfileCreate

class CaregiverCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    profile: CaregiverProfileCreate

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    age: Optional[int] = None
    phone: Optional[str] = None
    guardian_phone: Optional[str] = None
    role: Optional[str] = None

class CancerInfoCreate(BaseModel):
    cancer_type: str
    stage: str
    treatment_plan: str
    estimated_cost: float

class CancerInfoOut(BaseModel):
    cancer_type: str
    stage: str
    treatment_plan: str
    estimated_cost: float
    class Config:
         from_attributes = True


class ReminderCreate(BaseModel):
    title: str
    description: str
    reminder_time: datetime

class ReminderOut(BaseModel):
    id: int
    title: str
    description: str
    reminder_time: datetime
    class Config:
         from_attributes = True


class TodoCreate(BaseModel):
    task: str

class TodoOut(BaseModel):
    id: int
    task: str
    completed: bool
    class Config:
          from_attributes = True


class MedicalRecordOut(BaseModel):
    id: int
    patient_id: int
    doctor_id: int
    file_path: str
    description: str
    upload_time: datetime
    class Config:
          from_attributes = True


# --------------------
# Dependency: DB session
# --------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --------------------
# Authentication Helper Functions
# --------------------
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not user.hashed_password:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
         status_code=status.HTTP_401_UNAUTHORIZED,
         detail="Could not validate credentials",
         headers={"WWW-Authenticate": "Bearer"},
    )
    try:
         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
         email: str = payload.get("sub")
         if email is None:
              raise credentials_exception
    except JWTError:
         raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None:
         raise credentials_exception
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# Modified require_role to allow admin access to all endpoints
def require_role(role: str):
    def role_checker(current_user: User = Depends(get_current_active_user)):
         if current_user.role == "admin":
              return current_user
         if current_user.role != role:
              raise HTTPException(status_code=403, detail="Not enough permissions")
         return current_user
    return role_checker

# --------------------
# FastAPI App Initialization
# --------------------
app = FastAPI()

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    db = SessionLocal()
    try:
        admin = get_user_by_email(db, "admin@admin.com")
        if not admin:
            admin = User(
                name="admin",
                email="admin@admin.com",
                hashed_password=get_password_hash("admin"),
                age=30,
                phone="0000000000",
                role="admin"
            )
            db.add(admin)
            db.commit()
    except Exception as e:
        db.rollback()
        print("Admin seeding error (probably already exists):", e)
    finally:
        db.close()

# --------------------
# Login Endpoints
# --------------------
# Admin login
@app.post("/admin/token")
def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user or user.role != "admin":
         raise HTTPException(status_code=400, detail="Invalid admin credentials")
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# Patient login (using patient id and name)
@app.post("/patient/token")
def patient_login(patient_id: int, name: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == patient_id, User.name == name, User.role == "patient").first()
    if not user:
         raise HTTPException(status_code=400, detail="Invalid patient credentials")
    token = create_access_token(data={"sub": user.email if user.email else f"patient{user.id}"})
    return {"access_token": token, "token_type": "bearer"}

# Doctor login (using doctor id and name)
@app.post("/doctor/token")
def doctor_login(doctor_id: int, name: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == doctor_id, User.name == name, User.role == "doctor").first()
    if not user:
         raise HTTPException(status_code=400, detail="Invalid doctor credentials")
    token = create_access_token(data={"sub": user.email if user.email else f"doctor{user.id}"})
    return {"access_token": token, "token_type": "bearer"}

# Caregiver login (using caregiver id and name)
@app.post("/caregiver/token")
def caregiver_login(caregiver_id: int, name: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == caregiver_id, User.name == name, User.role == "caregiver").first()
    if not user:
         raise HTTPException(status_code=400, detail="Invalid caregiver credentials")
    token = create_access_token(data={"sub": user.email if user.email else f"caregiver{user.id}"})
    return {"access_token": token, "token_type": "bearer"}

# --------------------
# Common Endpoints
# --------------------
@app.post("/cancer-info", response_model=CancerInfoOut)
def add_cancer_info(info: CancerInfoCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if current_user.role not in ["patient", "admin"]:
         raise HTTPException(status_code=403, detail="Only patients or admin can add cancer info")
    cancer_info = CancerInfo(
         user_id=current_user.id,
         cancer_type=info.cancer_type,
         stage=info.stage,
         treatment_plan=info.treatment_plan,
         estimated_cost=info.estimated_cost
    )
    db.add(cancer_info)
    db.commit()
    db.refresh(cancer_info)
    return cancer_info

# (Other endpoints for reminders, todos, and medical records are assumed to be similar to previous implementations)
# For brevity, they are not repeated here.

# --------------------
# Doctor Dashboard Endpoints
# --------------------
@app.get("/patients", response_model=List[UserOut])
def list_patients(search: Optional[str] = None, current_user: User = Depends(require_role("doctor")), db: Session = Depends(get_db)):
    query = db.query(User).filter(User.role == "patient")
    if search:
         query = query.filter(User.name.ilike(f"%{search}%"))
    return query.all()

@app.post("/doctor-patients")
def add_doctor_patient(patient_id: int, current_user: User = Depends(require_role("doctor")), db: Session = Depends(get_db)):
    patient = db.query(User).filter(User.id == patient_id, User.role == "patient").first()
    if not patient:
         raise HTTPException(status_code=404, detail="Patient not found")
    association = db.query(DoctorPatient).filter(
         DoctorPatient.doctor_id == current_user.id,
         DoctorPatient.patient_id == patient_id
    ).first()
    if association:
         raise HTTPException(status_code=400, detail="Patient already claimed")
    new_assoc = DoctorPatient(doctor_id=current_user.id, patient_id=patient_id)
    db.add(new_assoc)
    db.commit()
    return {"detail": "Patient successfully added to your list."}

@app.get("/doctor-patients", response_model=List[UserOut])
def get_doctor_patients(current_user: User = Depends(require_role("doctor")), db: Session = Depends(get_db)):
    associations = db.query(DoctorPatient).filter(DoctorPatient.doctor_id == current_user.id).all()
    patient_ids = [assoc.patient_id for assoc in associations]
    patients = db.query(User).filter(User.id.in_(patient_ids)).all()
    return patients

# --------------------
# Admin Dashboard Endpoints
# --------------------
# Patient CRUD endpoints
@app.get("/admin/patients", response_model=List[dict])
def admin_get_patients(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    patients = db.query(User).filter(User.role == "patient").all()
    result = []
    for p in patients:
         profile = p.patient_profile.__dict__ if p.patient_profile else {}
         profile.pop("_sa_instance_state", None)
         result.append({
             "id": p.id,
             "name": p.name,
             "age": p.age,
             "phone": p.phone,
             "email": p.email,
             "profile": profile
         })
    return result

@app.post("/admin/patients", response_model=dict)
def admin_create_patient(patient: PatientCreate, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, patient.email)
    if db_user:
         raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(patient.password)
    new_user = User(
         name=patient.name,
         email=patient.email,
         hashed_password=hashed_password,
         age=patient.age,
         phone=patient.phone,
         guardian_phone=patient.guardian_phone,
         role="patient"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    profile = PatientProfile(
         user_id=new_user.id,
         blood_group=patient.profile.blood_group,
         native_place=patient.profile.native_place,
         height=patient.profile.height,
         weight=patient.profile.weight,
         disease_name=patient.profile.disease_name,
         disease_stage=patient.profile.disease_stage,
         caretaker=patient.profile.caretaker,
         allergy_details=patient.profile.allergy_details
    )
    db.add(profile)
    db.commit()
    return {"detail": "Patient created successfully", "patient_id": new_user.id}

@app.put("/admin/patients/{patient_id}", response_model=UserOut)
def admin_update_patient(patient_id: int, user_update: UserUpdate, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    user_obj = db.query(User).filter(User.id == patient_id, User.role == "patient").first()
    if not user_obj:
         raise HTTPException(status_code=404, detail="Patient not found")
    if user_update.name is not None:
         user_obj.name = user_update.name
    if user_update.email is not None:
         user_obj.email = user_update.email
    if user_update.age is not None:
         user_obj.age = user_update.age
    if user_update.phone is not None:
         user_obj.phone = user_update.phone
    if user_update.guardian_phone is not None:
         user_obj.guardian_phone = user_update.guardian_phone
    if user_update.password is not None:
         user_obj.hashed_password = get_password_hash(user_update.password)
    db.commit()
    db.refresh(user_obj)
    return user_obj

@app.delete("/admin/patients/{patient_id}")
def admin_delete_patient(patient_id: int, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    user_obj = db.query(User).filter(User.id == patient_id, User.role == "patient").first()
    if not user_obj:
         raise HTTPException(status_code=404, detail="Patient not found")
    db.delete(user_obj)
    db.commit()
    return {"detail": "Patient deleted"}

# Doctor CRUD endpoints
@app.post("/admin/doctors", response_model=dict)
def admin_create_doctor(doctor: DoctorCreate, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, doctor.email)
    if db_user:
         raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(doctor.password)
    new_user = User(
         name=doctor.name,
         email=doctor.email,
         hashed_password=hashed_password,
         age=doctor.age,
         phone=doctor.phone,
         guardian_phone=doctor.guardian_phone,
         role="doctor"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    profile = DoctorProfile(
         user_id=new_user.id,
         experience=doctor.profile.experience,
         domain=doctor.profile.domain,
         available_time=doctor.profile.available_time,
         place=doctor.profile.place,
         price_per_consulting=doctor.profile.price_per_consulting
    )
    db.add(profile)
    db.commit()
    return {"detail": "Doctor created successfully", "doctor_id": new_user.id}

@app.delete("/admin/doctors/{doctor_id}")
def admin_delete_doctor(doctor_id: int, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    user_obj = db.query(User).filter(User.id == doctor_id, User.role == "doctor").first()
    if not user_obj:
         raise HTTPException(status_code=404, detail="Doctor not found")
    db.delete(user_obj)
    db.commit()
    return {"detail": "Doctor deleted"}

# Caregiver CRUD endpoints
@app.post("/admin/caregivers", response_model=dict)
def admin_create_caregiver(caregiver: CaregiverCreate, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, caregiver.email)
    if db_user:
         raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(caregiver.password)
    new_user = User(
         name=caregiver.name,
         email=caregiver.email,
         hashed_password=hashed_password,
         age=caregiver.age,
         phone=caregiver.phone,
         guardian_phone=caregiver.guardian_phone,
         role="caregiver"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    profile = CaregiverProfile(
         user_id=new_user.id,
         blood_group=caregiver.profile.blood_group,
         place=caregiver.profile.place,
         experience=caregiver.profile.experience,
         price_per_day=caregiver.profile.price_per_day
    )
    db.add(profile)
    db.commit()
    return {"detail": "Caregiver created successfully", "caregiver_id": new_user.id}

@app.delete("/admin/caregivers/{caregiver_id}")
def admin_delete_caregiver(caregiver_id: int, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    user_obj = db.query(User).filter(User.id == caregiver_id, User.role == "caregiver").first()
    if not user_obj:
         raise HTTPException(status_code=404, detail="Caregiver not found")
    db.delete(user_obj)
    db.commit()
    return {"detail": "Caregiver deleted"}


# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
