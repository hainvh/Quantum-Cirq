import json
import re
import sys
from datetime import timedelta, datetime
from os import remove
from os.path import exists
from typing import List, Union

from qiskit import QuantumCircuit, execute
from qiskit_aer import Aer
from qiskit_ibm_runtime import QiskitRuntimeService

import app as app
import cirq
import script
from cirq.contrib.qasm_import import circuit_from_qasm
from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File
import uvicorn
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from quantastica.qps_api import QPS
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Authentication
SECRET_KEY = "963961892d0951644b3ed952deeef2ad6d77717822718dc4144ab06c63fca51a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24*60
# QiskitRuntimeService.save_account(channel="ibm_quantum", token="7dc70fd10ae119499c27f664f114ad5527b4975c57be4074677d921f8f2e60bf7b4732f46e936edb0a84f4df8d6e09b8efadbd25b19fc9971e76cf197c6c8093")


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
    try:
        request_json = await request.body()
        quirk_json = json.loads(request_json)
        circuit = cirq.quirk_json_to_circuit(quirk_json)
        qasm = cirq.qasm(circuit)
        print(circuit)
        if re.search(b'\xe2\x80\xa2', request_json):
            pattern = r'// Operation: CH\((\d+),\s*(\d+)\).*(?:;\n\n)'
            match = re.search(pattern, qasm, flags=re.DOTALL)
            if match:
                result = re.sub(pattern, f'ch q[{match.group(1)}], q[{match.group(2)}];\n\n', qasm, flags=re.DOTALL)
                return result
        return qasm
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/json-to-qiskit", response_class=HTMLResponse)
async def jsonToQiskit(request: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    # str = await request.json()
    # c = cirq.quirk_json_to_circuit(str)
    # qasm = cirq.qasm(c)
    # qisk = QPS.converter.convert(qasm, "qasm", "qiskit")
    # return qisk
    try:
        quirk_json = json.loads(await request.body())
        circuit = cirq.quirk_json_to_circuit(quirk_json)
        qasm = cirq.qasm(circuit)
        qiskit_code = QPS.converter.convert(qasm, "qasm", "qiskit")
        return qiskit_code
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/qasm-to-qiskit", response_class=HTMLResponse)
async def qasmToQiskit(data: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    try:
        qasm = await data.body()
        decoded = qasm.decode("utf-8")
        qiskitc = QPS.converter.convert(decoded, "qasm", "qiskit")
        return qiskitc
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/qasm-file-to-qiskit", response_class=HTMLResponse)
async def qasmFileToQiskit(file: UploadFile = File(...)):
    try:
        contents = file.file.read()
        decoded = contents.decode("utf-8")
        qiskitc = QPS.converter.convert(decoded, "qasm", "qiskit")
        return qiskitc
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/qasm-file-to-json", response_class=HTMLResponse)
async def qasmFileToJson(file: UploadFile = File(...)):
    try:
        contents = file.file.read()
        decoded = contents.decode("utf-8")
        cirqJson = circuit_from_qasm(decoded)
        json = cirq.contrib.quirk.circuit_to_quirk_url(cirqJson)
        return json
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/qasm-to-json", response_class=HTMLResponse)
async def qasmToJson(request: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    q2j_dict = {
        "%7B": "{", "%7D": "}", "%22": '\"', "%3A": ":", "%5B": "[", "%5D": "]", "%2C": ",",
        '{"arg":"%280.5000%29%20pi","id":"Rzft"}': '"Z^½"', '{"arg":"%28-0.5000%29%20pi","id":"Rzft"}': '"Z^-½"',
        '{"arg":"%280.5000%29%20pi","id":"Ryft"}': '"Y^½"', '{"arg":"%28-0.5000%29%20pi","id":"Ryft"}': '"Y^-½"',
        '{"arg":"%280.5000%29%20pi","id":"Rxft"}': '"X^½"', '{"arg":"%28-0.5000%29%20pi","id":"Rxft"}': '"X^-½"',
        '{"arg":"%280.2500%29%20pi","id":"Rzft"}': '"Z^¼"', '{"arg":"%28-0.2500%29%20pi","id":"Rzft"}': '"Z^-¼"',
        '{"arg":"%280.2500%29%20pi","id":"Ryft"}': '"Y^¼"', '{"arg":"%28-0.2500%29%20pi","id":"Ryft"}': '"Y^-¼"',
        '{"arg":"%280.2500%29%20pi","id":"Rxft"}': '"X^¼"', '{"arg":"%28-0.2500%29%20pi","id":"Rxft"}': '"X^-¼"'
    }
    try:
        qasm = await request.body()
        decoded = qasm.decode("utf-8")
        cirqJson = circuit_from_qasm(decoded)
        json = cirq.contrib.quirk.circuit_to_quirk_url(cirqJson)
        jsonQuirk = json[35:len(json)]
        for key in q2j_dict:
            if key in jsonQuirk:
                jsonQuirk = jsonQuirk.replace(key, q2j_dict[key])
        return jsonQuirk
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/qasm-qiskit-run")
async def qasmQiskitRun(request: Request):
    qasm = await request.body()
    decoded = qasm.decode("utf-8")
    qc = QuantumCircuit.from_qasm_str(decoded)
    backend = Aer.get_backend('qasm_simulator')
    job = execute(qc, backend=backend, shots=1024)
    job_result = job.result()
    result = job_result.get_counts(qc)

    return result


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


@app.post("/test/qiskit", response_class=HTMLResponse)
async def test(request: Request):
    qisk = await request.body()
    circ = qisk.decode("utf-8")
    circ
    # circ = QuantumCircuit(2)
    # circ.h(0)
    # circ.cx(0, 1)
    # circ.measure_all()

    # simulator = Aer.get_backend('aer_simulator')
    # circ = transpile(circ, simulator)
    #
    # shots = 10000
    #
    # sim_stabilizer = Aer.get_backend('aer_simulator_stabilizer')
    # job_stabilizer = sim_stabilizer.run(circ, shots=shots)
    # counts_stabilizer = job_stabilizer.result().get_counts(0)
    #
    # sim_statevector = Aer.get_backend('aer_simulator_statevector')
    # job_statevector = sim_statevector.run(circ, shots=shots)
    # counts_statevector = job_statevector.result().get_counts(0)
    #
    # sim_density = Aer.get_backend('aer_simulator_density_matrix')
    # job_density = sim_density.run(circ, shots=shots)
    # counts_density = job_density.result().get_counts(0)
    #
    # sim_mps = Aer.get_backend('aer_simulator_matrix_product_state')
    # job_mps = sim_mps.run(circ, shots=shots)
    # counts_mps = job_mps.result().get_counts(0)
    # print(plot_histogram([counts_stabilizer, counts_statevector, counts_density, counts_mps],
    #                      title='Counts for different simulation methods',
    #                      legend=['stabilizer', 'statevector',
    #                              'density_matrix', 'matrix_product_state']))
    # print(counts_statevector)
    # return counts_statevector
    return circ


# write qasm -> qiskit later
@app.post("/test/sh")
async def shTest(request: Request):
    if exists("generated.py"):
        remove("generated.py")
    fname = 'generated.py'
    data = await request.body()
    decoded = data.decode()
    with open(fname, 'w') as f:
        f.write(decoded)
    import generated
    data = generated.job_result.get_counts(generated.qc)
    remove("generated.py")
    return data


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
