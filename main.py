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
SECRET_KEY = "your_secret_key"  # change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
         expire = datetime.utcnow() + expires_delta
    else:
         expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --------------------
# Database Models
# --------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    age = Column(Integer)
    phone = Column(String)
    guardian_phone = Column(String, nullable=True)
    role = Column(String)  # valid roles: "patient", "caregiver", "doctor", "admin"
    # One-to-one relationship (if the patient provides cancer info)
    cancer_info = relationship("CancerInfo", back_populates="user", uselist=False)

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

# --------------------
# Pydantic Schemas
# --------------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    role: str  # one of "patient", "caregiver", "doctor", "admin"

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    age: int
    phone: str
    guardian_phone: Optional[str] = None
    role: str

    class Config:
        orm_mode = True

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
        orm_mode = True

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
        orm_mode = True

class TodoCreate(BaseModel):
    task: str

class TodoOut(BaseModel):
    id: int
    task: str
    completed: bool

    class Config:
        orm_mode = True

class MedicalRecordOut(BaseModel):
    id: int
    patient_id: int
    doctor_id: int
    file_path: str
    description: str
    upload_time: datetime

    class Config:
        orm_mode = True

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
    if not user:
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
         # Admin can perform all actions
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

# Create tables on startup
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # Create uploads directory if not exists
    if not os.path.exists("uploads"):
        os.makedirs("uploads")

# --------------------
# Routes / Endpoints
# --------------------

# Registration
@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
         raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(
         name=user.name,
         email=user.email,
         hashed_password=hashed_password,
         age=user.age,
         phone=user.phone,
         guardian_phone=user.guardian_phone,
         role=user.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Token (Login)
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
         raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
         data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Cancer Related Information (for patients or admin)
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

# CRUD for Meditation Reminder
@app.post("/reminders", response_model=ReminderOut)
def create_reminder(reminder: ReminderCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    new_reminder = Reminder(
         user_id=current_user.id,
         title=reminder.title,
         description=reminder.description,
         reminder_time=reminder.reminder_time
    )
    db.add(new_reminder)
    db.commit()
    db.refresh(new_reminder)
    return new_reminder

@app.get("/reminders", response_model=List[ReminderOut])
def get_reminders(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    reminders = db.query(Reminder).filter(Reminder.user_id == current_user.id).all()
    return reminders

@app.put("/reminders/{reminder_id}", response_model=ReminderOut)
def update_reminder(reminder_id: int, reminder: ReminderCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_reminder = db.query(Reminder).filter(Reminder.id == reminder_id, Reminder.user_id == current_user.id).first()
    if not db_reminder:
         raise HTTPException(status_code=404, detail="Reminder not found")
    db_reminder.title = reminder.title
    db_reminder.description = reminder.description
    db_reminder.reminder_time = reminder.reminder_time
    db.commit()
    db.refresh(db_reminder)
    return db_reminder

@app.delete("/reminders/{reminder_id}")
def delete_reminder(reminder_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_reminder = db.query(Reminder).filter(Reminder.id == reminder_id, Reminder.user_id == current_user.id).first()
    if not db_reminder:
         raise HTTPException(status_code=404, detail="Reminder not found")
    db.delete(db_reminder)
    db.commit()
    return {"detail": "Reminder deleted"}

# CRUD for Todo List (Daily Activities)
@app.post("/todos", response_model=TodoOut)
def create_todo(todo: TodoCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    new_todo = Todo(
         user_id=current_user.id,
         task=todo.task,
         completed=False
    )
    db.add(new_todo)
    db.commit()
    db.refresh(new_todo)
    return new_todo

@app.get("/todos", response_model=List[TodoOut])
def get_todos(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    todos = db.query(Todo).filter(Todo.user_id == current_user.id).all()
    return todos

@app.put("/todos/{todo_id}", response_model=TodoOut)
def update_todo(todo_id: int, todo: TodoCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_todo = db.query(Todo).filter(Todo.id == todo_id, Todo.user_id == current_user.id).first()
    if not db_todo:
         raise HTTPException(status_code=404, detail="Todo not found")
    db_todo.task = todo.task
    db.commit()
    db.refresh(db_todo)
    return db_todo

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_todo = db.query(Todo).filter(Todo.id == todo_id, Todo.user_id == current_user.id).first()
    if not db_todo:
         raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(db_todo)
    db.commit()
    return {"detail": "Todo deleted"}

# Caregiver Recruitment - List available caregivers
@app.get("/caregivers", response_model=List[UserOut])
def list_caregivers(db: Session = Depends(get_db)):
    caregivers = db.query(User).filter(User.role == "caregiver").all()
    return caregivers

# Medical Records Upload & View
UPLOAD_DIR = "uploads"

@app.post("/medical-records", response_model=MedicalRecordOut)
def upload_medical_record(
    patient_id: int,
    description: str,
    file: UploadFile = File(...),
    current_user: User = Depends(require_role("doctor")),
    db: Session = Depends(get_db)
):
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb+") as f:
         f.write(file.file.read())
    record = MedicalRecord(
         patient_id=patient_id,
         doctor_id=current_user.id,
         file_path=file_location,
         description=description
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

@app.get("/medical-records", response_model=List[MedicalRecordOut])
def get_medical_records(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    # Patients see their records; doctors see records they uploaded.
    if current_user.role == "patient":
         records = db.query(MedicalRecord).filter(MedicalRecord.patient_id == current_user.id).all()
    elif current_user.role in ["doctor", "admin"]:
         records = db.query(MedicalRecord).filter(MedicalRecord.doctor_id == current_user.id).all()
    else:
         raise HTTPException(status_code=403, detail="Not enough permissions")
    return records

# --------------------
# Run the app (for example, using: uvicorn main:app --reload)
# --------------------
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
