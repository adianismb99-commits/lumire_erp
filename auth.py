from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from database import get_supabase

SECRET_KEY = "lumire-super-secret-key-cambiar-en-produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    print(f"Intentando login con email: {email}")  # <-- Agrega esto
    supabase = get_supabase()
    user = supabase.table("usuarios").select("*").eq("email", email).execute()
    
    print(f"Usuario encontrado: {user.data}")  # <-- Agrega esto
    
    if not user.data:
        print("Usuario no encontrado")
        return False
    user_data = user.data[0]
    
    print(f"Contraseña guardada: {user_data['password_hash']}")  # <-- Agrega esto
    
    if not verify_password(password, user_data["password_hash"]):
        print("Contraseña incorrecta")
        return False
    return user_data

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    supabase = get_supabase()
    user = supabase.table("usuarios").select("*, roles(*)").eq("id", user_id).execute()
    if not user.data:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return user.data[0]

def has_permission(user, modulo: str, accion: str):
    supabase = get_supabase()
    rol_id = user["rol_id"]
    
    permisos = supabase.table("roles_permisos").select("permisos(*)").eq("rol_id", rol_id).execute()
    for permiso in permisos.data:
        p = permiso["permisos"]
        if p["modulo"] == modulo and p["accion"] == accion:
            return True
    return False