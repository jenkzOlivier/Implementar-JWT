from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional

# chave secreta
SECRET_KEY = "H264TESTE"
# JWT token espira em 30 minutos
TOKEN_EXPIRATION = timedelta(minutes=30)

app = FastAPI()


class User(BaseModel):
    name: str
    email: str
    password: str

users_db = []


password_hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

# hash de senha
def hash_password(password: str):
    return password_hasher.hash(password)

# verificar senha
def verify_password(plain_password, hashed_password):
    return password_hasher.verify(plain_password, hashed_password)

# Autentificação jwt
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

# rota de resgistro
@app.post("/users/", response_model=User)
def create_user(user: User):
    # Hash de senha
    hashed_password = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, password=hashed_password)
    users_db.append(new_user)
    return new_user

# lista de todos os usuarios
@app.get("/users/", response_model=List[User])
def get_users():
    return users_db

# usuario especifico pelo email
@app.get("/users/{email}", response_model=User)
def get_user(email: str):
    for user in users_db:
        if user.email == email:
            return user
    raise HTTPException(status_code=404, detail="User not found")

# JWT criação de tokens para rota
@app.post("/token/")
def login_for_access_token(user: User):
    found_user = None
    for u in users_db:
        if u.email == user.email:
            found_user = u
            break
    if found_user is None or not verify_password(user.password, found_user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": found_user.email}, expires_delta=TOKEN_EXPIRATION)
    return {"access_token": access_token, "token_type": "bearer"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
