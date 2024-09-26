from pymongo.mongo_client import MongoClient
from fastapi import FastAPI , HTTPException
import bcrypt
from typing import Optional
from pydantic import BaseModel,EmailStr, constr, FieldValidationInfo, field_validator

app = FastAPI()
url = "mongodb://localhost:27017/api.py"
client = MongoClient(url)
try:
    client.admin.command('ping')
    print("You have sucessfully connected to MONGODB")
except Exception as e:
    print(e)

db = client["mydatabase"]
users_collection = db["user_profile"]

class User(BaseModel):
    first_name:str
    last_name:str
    email: EmailStr
    password: constr(min_length=8) # type: ignore
    confirm_password:str

@field_validator('confirm_password')
def passwords_match(cls, v, info: FieldValidationInfo):
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=8) # type: ignore

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

@app.post("/signup")
def sign_up(user: User):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)
    user_dict = user.dict()
    user_dict['email'] = user_dict['email'].lower()
    user_dict['password'] = hashed_password
    del user_dict['confirm_password']
    result = users_collection.insert_one(user_dict)
    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}

def verify_password(plain_password:str, hashed_password:str)->bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
@app.post("/login")
def login(user:UserLogin):
    db_user = users_collection.find_one({"email":user.email.lower()})

    if not db_user:
        raise HTTPException(status_code=400,detail="Invalid email or password")
    
    if not verify_password(user.password,db_user['password']):
        raise HTTPException(status_code=400,detail="Invalid email or password")
    return{"messsage":"login Successful","user_id":str(db_user['_id'])}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8003)