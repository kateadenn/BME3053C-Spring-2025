from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import jwt
from datetime import datetime, timedelta

# Initialize FastAPI app
app = FastAPI(title="Patient Management System API")

# Secret key for JWT token
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Data Models
class PatientBase(BaseModel):
    name: str
    age: int
    condition: str
    medical_history: Optional[str] = None

class PatientCreate(PatientBase):
    pass

class Patient(PatientBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

# Mock database
patients_db = {}
user_db = {"admin": {"username": "admin", "password": "admin123"}}

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return username

# API Endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = user_db.get(form_data.username)
    if not user or form_data.password != user["password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/patients/", response_model=Patient)
async def create_patient(patient: PatientCreate, username: str = Depends(get_current_user)):
    patient_id = len(patients_db) + 1
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": datetime.now()
    })
    patients_db[patient_id] = patient_dict
    return patient_dict

@app.get("/patients/", response_model=List[Patient])
async def read_patients(skip: int = 0, limit: int = 10, username: str = Depends(get_current_user)):
    return list(patients_db.values())[skip : skip + limit]

@app.get("/patients/{patient_id}", response_model=Patient)
async def read_patient(patient_id: int, username: str = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patients_db[patient_id]

@app.put("/patients/{patient_id}", response_model=Patient)
async def update_patient(
    patient_id: int, 
    patient: PatientCreate, 
    username: str = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": patients_db[patient_id]["created_at"]
    })
    patients_db[patient_id] = patient_dict
    return patient_dict