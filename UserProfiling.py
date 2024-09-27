from pymongo.mongo_client import MongoClient
from fastapi import FastAPI , HTTPException
import bcrypt
from typing import Optional , Dict
from pydantic import BaseModel,EmailStr, constr, FieldValidationInfo, field_validator
from bson import ObjectId

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

class UserProfileUpdate(BaseModel):
    first_name:Optional[str]
    last_name:Optional[str]
    preferences:Optional[Dict[str,str]]

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

def verify_password(plain_password:str, hashed_password:str)->bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.post("/signup")
def sign_up(user: User):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)
    user_dict = user.dict()
    user_dict['email'] = user_dict['email'].lower()
    user_dict['password'] = hashed_password
    user_dict['preferences']={}
    del user_dict['confirm_password']
    result = users_collection.insert_one(user_dict)
    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}


@app.post("/login")
def login(user:UserLogin):
    db_user = users_collection.find_one({"email":user.email.lower()})

    if not db_user:
        raise HTTPException(status_code=400,detail="Invalid email or password")
    
    if not verify_password(user.password,db_user['password']):
        raise HTTPException(status_code=400,detail="Invalid email or password")
    return{"messsage":"login Successful","user_id":str(db_user['_id'])}

def get_user_or_404(user_id: str):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Endpoint: Get User Profile
@app.get("/profile/{user_id}")
def get_user_profile(user_id: str):
    user = get_user_or_404(user_id)
    user['_id'] = str(user['_id'])  # Convert ObjectId to string for JSON response
    return user

# Endpoint: Update User Profile
@app.put("/profile/update/{user_id}")
def update_user_profile(user_id: str, update_data: UserProfileUpdate):
    user = get_user_or_404(user_id)
    update_fields = {k: v for k, v in update_data.dict().items() if v is not None}  # Filter out None values

    if update_fields:
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_fields})
        return {"message": "User profile updated successfully", "updated_fields": update_fields}
    return {"message": "No fields to update"}

# Endpoint: Delete User Profile
@app.delete("/profile/delete/{user_id}")
def delete_user_profile(user_id: str):
    user = get_user_or_404(user_id)
    users_collection.delete_one({"_id": ObjectId(user_id)})
    return {"message": f"User profile with ID {user_id} deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8003)