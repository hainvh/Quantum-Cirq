import json
import re
from datetime import timedelta, datetime
from typing import List, Union

from kaleidoscope import qsphere, bloch_multi_disc
from qiskit import QuantumCircuit, execute, BasicAer
from qiskit_aer import Aer

import app as app
import cirq
from cirq.contrib.qasm_import import circuit_from_qasm
from fastapi import FastAPI, Request, Depends, HTTPException, status
import uvicorn
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from passlib.hash import bcrypt
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from quantastica.qps_api import QPS
from fastapi.middleware.cors import CORSMiddleware
import loginCredentials

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
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60

# username: username
# password: secret; change the password here
password = loginCredentials.password
fake_user = {
    "username": {
        "username": loginCredentials.username,
        "email": "a@example.com",
        "hashed_password": bcrypt.hash(password),
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


"""
    Endpoint to convert Quirk JSON to OpenQASM 2.0. Convert from JSON to Cirq to OpenQASM.
    
    The JSON gates S, S-dagger, T, T-dagger and any control gates such as CH are specifically changed to match 
    conventional OpenQASM language.
"""


@app.post("/json-to-qasm", response_class=HTMLResponse)
async def jsonToQASM(request: Request):
    j2q_dict = {
        "rz(pi*0.5)": "s", "rz(pi*-0.5)": "sdg",
        "rz(pi*0.25)": "t", "rz(pi*-0.25)": "tdg"
    }
    try:
        request_json = await request.body()
        quirk_json = json.loads(request_json)
        circuit = cirq.quirk_json_to_circuit(quirk_json)
        qasm = cirq.qasm(circuit)
        if re.search(b'\xe2\x80\xa2', request_json):
            qasm += "\n\n"
            pattern = r'// Operation: C(\w+)\((\d+),\s*(\d+)\).*?(?:;\n\n)'
            while True:
                match = re.search(pattern, qasm, flags=re.DOTALL)
                if match is None:
                    break
                qasm = re.sub(pattern, f'c{str.lower(match.group(1))} q[{match.group(2)}], q[{match.group(3)}];\n\n',
                              qasm, flags=re.DOTALL, count=1)
        for key in j2q_dict:
            if key in qasm:
                qasm = qasm.replace(key, j2q_dict[key])
        return qasm
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


"""
    Endpoint to convert OpenQASM 2.0 to Qiskit.
    QASM to Qiskit code converted using Quantastica's QPS converter. 
    QPS automatically adds a Qiskit backend run function, which is removed here to use other run functions.
"""


@app.post("/qasm-to-qiskit", response_class=HTMLResponse)
async def qasmToQiskit(data: Request, current_user: User = Depends(get_current_active_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    try:
        qasm = await data.body()
        decoded = qasm.decode("utf-8")
        qiskitc = QPS.converter.convert(decoded, "qasm", "qiskit")
        # don't change the code_to_remove it breaks the .replace
        code_to_remove = "backend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend=backend, shots=shots)\njob_result = job.result()\nprint(job_result.get_counts(qc))"
        qiskitc = qiskitc.replace(code_to_remove, "")
        return qiskitc
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


"""
    Endpoint to convert OpenQASM 2.0 to Quirk JSON. Convert from QASM to Cirq to JSON.
    The QASM gates S, S-dagger, T, T-dagger, Y^1/2, Y^-1/2, X^1/2, X^-1/2, Y^1/4, Y^-1/4, X^1/4, X^-1/4 are
    specifically converted to the correct JSON format.
"""


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
        '{"arg":"%280.2500%29%20pi","id":"Rxft"}': '"X^¼"', '{"arg":"%28-0.2500%29%20pi","id":"Rxft"}': '"X^-¼"',
        'Z%5E%C2%BD': 'Z^½', 'Z%5E-%C2%BD': 'Z^-½', 'Z%5E%C2%BC': 'Z^¼', 'Z%5E-%C2%BC': 'Z^-¼'
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


"""
    Endpoint to run OpenQASM 2.0 code on a Qiskit backend. Uses the 'qasm_simulator' backend and return qubit counts.
    Currently a placeholder. Can be changed to desired result given more in-depth specifications.
"""


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


"""
    Endpoint to verify user's login credential. Change the credentials in 'loginCredentials.py'.
"""


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


"""
    Endpoint to return data to draw a histogram for the frontend bar chart. 
    Takes Qiskit code and execute it to return the resulting counts. The counts are then filtered into key: value pairs,
    converted to JSON and then returned to the frontend for processing.
"""


@app.post("/return-histogram", response_class=HTMLResponse)
async def returnHistogram(request: Request):
    try:
        # if exists("generatedBar.py"):
        #     remove("generatedBar.py")
        # file = "generatedBar.py"
        data = await request.body()
        check1 = "from qiskit import QuantumRegister, ClassicalRegister"
        check2 = "from qiskit import QuantumCircuit, execute, Aer"
        if data.splitlines()[0] == check1.encode() and data.splitlines()[1] == check2.encode():
            code_obj = compile(data, '<string>', 'exec')
            exec_result = exec(code_obj)
        else:
            return "Upload code error"
        bit_counts = locals()['counts']
        bar_data = [{'State': key, 'Probability': value / 10} for key, value in bit_counts.items()]
        for d in bar_data:
            d['State'] = "".join(d['State'].split())
            d['Probability'] = str(d['Probability'])
        #         decoded = data.decode()
        #         with open(file, "w") as f:
        #             f.write(decoded)
        #             f.write("""
        # from qiskit import BasicAer
        # backend = BasicAer.get_backend('statevector_simulator')
        # job = execute(qc, backend=backend, shots=shots)
        # job_result = job.result()
        # counts = job_result.get_counts(qc)
        #             """)
        #         import generatedBar
        #         bar_data = [{'State': key, 'Probability': value} for key, value in generatedBar.counts.items()]
        #         remove("generatedBar.py")
        return json.dumps(bar_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


"""
    Endpoint to return data to draw a qsphere for the frontend bar chart. 
    Takes Qiskit code and execute it to return a PlotlyWidget object.
    The object is then converted to HTML text and is returned to the frontend.
"""


@app.post("/return-qsphere", response_class=HTMLResponse)
async def returnQSphere(request: Request):
    try:
        # if exists("generatedSphere.py"):
        #     remove("generatedSphere.py")
        # file = "generatedSphere.py"
        data = await request.body()
        # decoded = data.decode()
        check1 = "from qiskit import QuantumRegister, ClassicalRegister"
        check2 = "from qiskit import QuantumCircuit, execute, Aer"
        if data.splitlines()[0] == check1.encode() and data.splitlines()[1] == check2.encode():
            code_obj = compile(data, '<string>', 'exec')
            exec_result = exec(code_obj)
        else:
            return "Upload code error"
        fig = qsphere(locals()['statevector'], as_widget=True)
        fig.update_layout(width=400, height=400)
        htmlText = fig.to_html(full_html=False, include_plotlyjs=False, div_id="bloch-sphere-return")
        # Get data through secondary .py file. Doesn't work. Leave it alone in case come back and fix.
        #         with open(file, "w") as f:
        #             f.write(decoded)
        #             f.write("""
        # from qiskit import BasicAer
        # backend = BasicAer.get_backend('statevector_simulator')
        # job = execute(qc, backend=backend, shots=shots)
        # job_result = job.result()
        # statevector = job_result.get_statevector()
        #             """)
        #         import generatedSphere
        #         fig = qsphere(generatedSphere.statevector, as_widget=True)
        #         fig.update_layout(width=500, height=500)
        #         # fig.show()
        #         htmlText = fig.to_html(full_html=False, include_plotlyjs=False, div_id="bloch-sphere-return")
        #         remove("generatedSphere.py")
        return htmlText
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


"""
    Endpoint to return data to draw a multi-disc for the frontend bar chart. 
    Takes Qiskit code and execute it to return a PlotlyWidget object.
    The object is then converted to HTML text and is returned to the frontend.
"""


@app.post("/return-bloch-disc", response_class=HTMLResponse)
async def returnBlochDisc(request: Request):
    try:
        # if exists("generatedDisc.py"):
        #     remove("generatedDisc.py")
        # file = "generatedDisc.py"
        data = await request.body()
        # decoded = data.decode()
        check1 = "from qiskit import QuantumRegister, ClassicalRegister"
        check2 = "from qiskit import QuantumCircuit, execute, Aer"
        if data.splitlines()[0] == check1.encode() and data.splitlines()[1] == check2.encode():
            code_obj = compile(data, '<string>', 'exec')
            exec_result = exec(code_obj)
        else:
            return "Upload code error"
        fig = bloch_multi_disc(locals()['statevector'], as_widget=True)
        fig.update_layout(width=500, height=500)
        htmlText = fig.to_html(full_html=False, include_plotlyjs=False, div_id="bloch-disc-return")
        #         decoded = data.decode()
        #         with open(file, "w") as f:
        #             f.write(decoded)
        #             f.write("""
        # from qiskit import BasicAer
        # import qiskit.quantum_info as qi
        # backend = BasicAer.get_backend('statevector_simulator')
        # job = execute(qc, backend=backend, shots=shots)
        # state = qi.Statevector(qc)
        #         """)
        #         import generatedDisc
        #         fig = bloch_multi_disc(generatedDisc.state, as_widget=True)
        #         htmlText = fig.to_html(full_html=False, include_plotlyjs=False, div_id="bloch_disc_return")
        #         remove("generatedDisc.py")
        return htmlText
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
