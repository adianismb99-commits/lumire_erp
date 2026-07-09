import os
from datetime import datetime, timedelta
from database import get_supabase
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

# ============================================
# BLOQUEO POR INTENTOS FALLIDOS
# ============================================

BLOQUEO_TIEMPO_MIN = 30  # minutos
MAX_INTENTOS_BLOQUEO = 3
MAX_INTENTOS_PERMANENTE = 5

def registrar_intento_fallido(email: str, ip: str = None, user_agent: str = None):
    supabase = get_supabase()
    
    # Verificar si ya existe registro para este email
    existing = supabase.table("intentos_fallidos").select("*").eq("email", email).execute()
    
    if existing.data:
        # Actualizar contador
        nuevo_intento = existing.data[0]["intentos"] + 1
        supabase.table("intentos_fallidos").update({
            "intentos": nuevo_intento,
            "fecha": datetime.now().isoformat(),
            "ip": ip,
            "user_agent": user_agent
        }).eq("email", email).execute()
        
        # Verificar si alcanzó el límite para bloqueo permanente
        if nuevo_intento >= MAX_INTENTOS_PERMANENTE:
            # Bloquear permanentemente
            supabase.table("usuarios_bloqueados").insert({
                "email": email,
                "motivo": f"5 intentos fallidos consecutivos",
                "bloqueado_por": "sistema_automatico"
            }).execute()
            return "permanente"
        
        return nuevo_intento
    else:
        # Nuevo registro
        supabase.table("intentos_fallidos").insert({
            "email": email,
            "ip": ip,
            "user_agent": user_agent,
            "intentos": 1,
            "fecha": datetime.now().isoformat()
        }).execute()
        return 1

def verificar_bloqueo(email: str):
    supabase = get_supabase()
    
    # 1. Verificar bloqueo permanente
    bloqueado = supabase.table("usuarios_bloqueados").select("*").eq("email", email).execute()
    if bloqueado.data:
        return {"bloqueado": True, "motivo": "Bloqueado permanentemente por múltiples intentos fallidos", "permanente": True}
    
    # 2. Verificar intentos fallidos (bloqueo temporal)
    intentos = supabase.table("intentos_fallidos").select("*").eq("email", email).execute()
    if intentos.data:
        datos = intentos.data[0]
        intentos_count = datos["intentos"]
        ultima_fecha = datetime.fromisoformat(datos["fecha"])
        tiempo_pasado = (datetime.now() - ultima_fecha).seconds / 60
        
        if intentos_count >= MAX_INTENTOS_BLOQUEO and tiempo_pasado < BLOQUEO_TIEMPO_MIN:
            return {
                "bloqueado": True,
                "motivo": f"Demasiados intentos fallidos. Bloqueado por {BLOQUEO_TIEMPO_MIN} minutos",
                "restante": round(BLOQUEO_TIEMPO_MIN - tiempo_pasado),
                "permanente": False
            }
    
    return {"bloqueado": False}