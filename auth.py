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
    supabase = get_supabase()
    user = supabase.table("usuarios").select("*").eq("email", email).execute()
    
    if not user.data:
        return False
    user_data = user.data[0]
    if not verify_password(password, user_data["password_hash"]):
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
        empresa_id: int = payload.get("empresa_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    supabase = get_supabase()
    user = supabase.table("usuarios").select("*, roles(*)").eq("id", user_id).execute()
    if not user.data:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    user_data = user.data[0]
    user_data["empresa_id"] = empresa_id  # Forzar empresa desde el token
    
    return user_data

def has_permission(user, modulo: str, accion: str):
    supabase = get_supabase()
    rol_id = user["rol_id"]
    
    permisos = supabase.table("roles_permisos").select("permisos(*)").eq("rol_id", rol_id).execute()
    for permiso in permisos.data:
        p = permiso["permisos"]
        if p["modulo"] == modulo and p["accion"] == accion:
            return True
    return False