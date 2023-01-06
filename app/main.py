from datetime import timedelta, datetime
from typing import List, Union

import cirq
from cirq.contrib.qasm_import import circuit_from_qasm
from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File
import uvicorn
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from quantastica.qps_api import QPS

# Authentication
SECRET_KEY = "963961892d0951644b3ed952deeef2ad6d77717822718dc4144ab06c63fca51a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# username: username
# password: secret
fake_user = {
    "username": {
        "username": "username",
        "email": "a@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# End of auth


app = FastAPI()


class Item(BaseModel):  # kế thừa từ class Basemodel và khai báo các biến
    link: str


class UploadText(BaseModel):
    data: str = ""


def verify_password(plain_pass, hashed_pass):
    return pwd_context.verify(plain_pass, hashed_pass)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    enconded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return enconded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_user, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/{name}")
async def read_item(name):
    return {"name": name}


@app.post("/json-to-qasm", response_class=HTMLResponse)
async def jsonToQASM(request: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    str = await request.json()
    # quirkJson = json.loads(str)
    c = cirq.quirk_json_to_circuit(str)
    code = cirq.qasm(c)
    return code


@app.post("/json-to-qiskit", response_class=HTMLResponse)
async def jsonToQiskit(request: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    str = await request.json()
    c = cirq.quirk_json_to_circuit(str)
    print(c)
    qasm = cirq.qasm(c)
    qisk = QPS.converter.convert(qasm, "qasm", "qiskit")
    return qisk


@app.post("/qasm-to-qiskit", response_class=HTMLResponse)
async def qasmToQiskit(data: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    qasm = await data.body()
    decoded = qasm.decode("utf-8")
    qiskitc = QPS.converter.convert(decoded, "qasm", "qiskit")
    return qiskitc


@app.post("/qasm-file-to-qiskit", response_class=HTMLResponse)
async def qasmFileToQiskit(file: UploadFile = File(...)):
    contents = file.file.read()
    decoded = contents.decode("utf-8")
    qiskitc = QPS.converter.convert(decoded, "qasm", "qiskit")
    return qiskitc


@app.post("/qasm-file-to-json", response_class=HTMLResponse)
async def qasmFileToJson(file: UploadFile = File(...)):
    contents = file.file.read()
    decoded = contents.decode("utf-8")
    cirqJson = circuit_from_qasm(decoded)
    json = cirq.contrib.quirk.circuit_to_quirk_url(cirqJson)
    return json


# qiskit to qasm not possible?
# qiskit to json not possible?


@app.post("/qasm-to-json", response_class=HTMLResponse)
async def qasmToJson(request: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    qasm = await request.body()
    decoded = qasm.decode("utf-8")
    cirqJson = circuit_from_qasm(decoded)
    json = cirq.contrib.quirk.circuit_to_quirk_url(cirqJson)
    jsonQuirk = json[35:len(json)]\
        .replace("%7B", "{").replace("%7D", "}")\
        .replace("%22", "\"")\
        .replace("%3A", ":")\
        .replace("%5B", "[").replace("%5D", "]").\
        replace("%2C", ",")
    return jsonQuirk


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_user, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
