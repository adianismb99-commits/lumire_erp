import os
import random
from datetime import datetime, timedelta
from jose import jwt
from fastapi import HTTPException, Depends
from notificaciones import enviar_correo
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from auth import get_current_user, has_permission, authenticate_user, create_access_token
from routes import productos, ventas, inventario, empleados, reportes

app = FastAPI(title="LUMIRE ERP API", version="1.0.0")

# ========== CORS - DEBE ESTAR ANTES DE LAS RUTAS ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lumire-erp-frontend.onrender.com",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Incluir rutas
app.include_router(productos.router, prefix="/api/productos", tags=["Productos"])
app.include_router(ventas.router, prefix="/api/ventas", tags=["Ventas"])
app.include_router(inventario.router, prefix="/api/inventario", tags=["Inventario"])
app.include_router(empleados.router, prefix="/api/empleados", tags=["Empleados"])
app.include_router(reportes.router, prefix="/api/reportes", tags=["Reportes"])

@app.get("/")
def root():
    return {"message": "LUMIRE ERP API - Funcionando"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/empresas")
def get_empresas():
    from database import get_supabase
    supabase = get_supabase()
    empresas = supabase.table("empresas").select("id, nombre").execute()
    return empresas.data

@app.post("/api/login")
def login(usuario: dict):
    email = usuario.get("email")
    password = usuario.get("password")
    empresa_id = usuario.get("empresa_id")
    
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    # Verificar que el usuario pertenece a la empresa seleccionada
    if user["empresa_id"] != empresa_id:
        raise HTTPException(status_code=401, detail="Usuario no pertenece a esta empresa")
    
    access_token = create_access_token(data={
        "sub": str(user["id"]),
        "empresa_id": empresa_id
    })
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@app.get("/api/usuarios/public")
def get_usuarios_public():
    from database import get_supabase
    supabase = get_supabase()
    response = supabase.rpc("get_public_users").execute()
    return response.data

@app.get("/api/usuarios/")
def get_usuarios(current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    if current_user["rol_id"] not in [1, 4]:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    usuarios = supabase.table("usuarios")\
        .select("id, nombre, email, rol_id, activo")\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    
    return usuarios.data

@app.post("/api/usuarios/register")
def register_usuario(usuario: dict, current_user=Depends(get_current_user)):
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    from database import get_supabase
    from auth import get_password_hash
    supabase = get_supabase()
    
    hashed = get_password_hash(usuario.get("password"))
    
    nuevo = supabase.table("usuarios").insert({
        "empresa_id": current_user["empresa_id"],
        "nombre": usuario.get("nombre"),
        "email": usuario.get("email"),
        "password_hash": hashed,
        "rol_id": usuario.get("rol_id")
    }).execute()
    
    return {"message": "Usuario creado", "id": nuevo.data[0]["id"]}

@app.put("/api/usuarios/{usuario_id}")
def update_usuario(usuario_id: int, usuario: dict, current_user=Depends(get_current_user)):
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    from database import get_supabase
    supabase = get_supabase()
    
    update_data = {
        "nombre": usuario.get("nombre"),
        "email": usuario.get("email"),
        "rol_id": usuario.get("rol_id")
    }
    
    if usuario.get("password"):
        from auth import get_password_hash
        update_data["password_hash"] = get_password_hash(usuario.get("password"))
    
    result = supabase.table("usuarios")\
        .update(update_data)\
        .eq("id", usuario_id)\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return {"message": "Usuario actualizado"}

@app.delete("/api/usuarios/{usuario_id}")
def delete_usuario(usuario_id: int, current_user=Depends(get_current_user)):
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    if usuario_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")
    
    from database import get_supabase
    supabase = get_supabase()
    
    result = supabase.table("usuarios")\
        .delete()\
        .eq("id", usuario_id)\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return {"message": "Usuario eliminado"}

@app.post("/api/usuarios/{usuario_id}/cambiar-pass")
def cambiar_password(usuario_id: int, data: dict, current_user=Depends(get_current_user)):
    from database import get_supabase
    from auth import verify_password, get_password_hash
    supabase = get_supabase()
    
    user = supabase.table("usuarios").select("*").eq("id", usuario_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not user.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user_data = user.data[0]
    
    if current_user["id"] == usuario_id:
        if not verify_password(data.get("pass_antigua"), user_data["password_hash"]):
            raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
    else:
        if current_user["rol_id"] != 1:
            raise HTTPException(status_code=403, detail="Sin permiso")
    
    nueva_password = get_password_hash(data.get("pass_nueva"))
    supabase.table("usuarios").update({"password_hash": nueva_password}).eq("id", usuario_id).execute()
    
    return {"message": "Contraseña actualizada"}

@app.get("/api/ventas/")
def get_ventas(current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    ventas = supabase.table("ventas")\
        .select("*")\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    
    return ventas.data

@app.get("/keepalive")
def keepalive():
    try:
        from database import get_supabase
        supabase = get_supabase()
        supabase.table("empresas").select("id").limit(1).execute()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}, 500
    
# ============================================
# RECUPERACIÓN DE CONTRASEÑA
# ============================================

RECOVERY_SECRET = "otro-secreto-para-recuperacion"  # Cámbialo en producción
RECOVERY_ALGORITHM = "HS256"
RECOVERY_EXPIRE_MINUTES = 60

@app.post("/api/auth/forgot-password")
def forgot_password(request: dict):
    email = request.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email es requerido")
    
    from database import get_supabase
    supabase = get_supabase()
    
    # Buscar usuario
    user = supabase.table("usuarios").select("id, email").eq("email", email).execute()
    if not user.data:
        # Por seguridad, devolvemos el mismo mensaje aunque no exista
        return {"message": "Si el correo existe, recibirás un enlace para restablecer tu contraseña"}
    
    user_id = user.data[0]["id"]
    
    # Generar token JWT
    token_data = {
        "sub": str(user_id), 
        "exp": datetime.utcnow() + timedelta(minutes=RECOVERY_EXPIRE_MINUTES)
    }
    token = jwt.encode(token_data, RECOVERY_SECRET, algorithm=RECOVERY_ALGORITHM)
    
    # Guardar token en la tabla tokens_recuperacion
    supabase.table("tokens_recuperacion").insert({
        "usuario_id": user_id,
        "token": token,
        "expira_en": (datetime.utcnow() + timedelta(minutes=RECOVERY_EXPIRE_MINUTES)).isoformat()
    }).execute()
    
    # Construir enlace
    frontend_url = os.getenv("FRONTEND_URL", "https://lumire-erp-frontend.onrender.com")
    enlace = f"{frontend_url}/reset-password?token={token}"
    
    cuerpo = f"""
    <h2>Recuperación de Contraseña - LUMIRE ERP</h2>
    <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
    <a href="{enlace}">{enlace}</a>
    <p>Este enlace expirará en {RECOVERY_EXPIRE_MINUTES} minutos.</p>
    <p>Si no solicitaste este cambio, ignora este correo.</p>
    """
    
    enviar_correo(email, "Recuperación de Contraseña - LUMIRE ERP", cuerpo)
    
    return {"message": "Correo enviado correctamente"}

@app.post("/api/auth/reset-password")
def reset_password(token: str, new_password: str):
    from database import get_supabase
    from auth import get_password_hash
    supabase = get_supabase()
    
    try:
        payload = jwt.decode(token, RECOVERY_SECRET, algorithms=[RECOVERY_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=400, detail="Token inválido")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El enlace ha expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Token inválido")
    
    # Verificar que el token no haya sido usado
    token_record = supabase.table("tokens_recuperacion").select("*").eq("token", token).eq("usado", False).execute()
    if not token_record.data:
        raise HTTPException(status_code=400, detail="Token ya usado o inválido")
    
    # Actualizar contraseña
    hashed = get_password_hash(new_password)
    supabase.table("usuarios").update({"password_hash": hashed}).eq("id", user_id).execute()
    
    # Marcar token como usado
    supabase.table("tokens_recuperacion").update({"usado": True}).eq("token", token).execute()
    
    return {"message": "Contraseña actualizada correctamente"}

@app.post("/api/auth/enable-2fa")
def enable_2fa(metodo: str, current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    # Generar código OTP de 6 dígitos
    codigo = str(random.randint(100000, 999999))
    expira = datetime.utcnow() + timedelta(minutes=5)
    
    # Guardar en tabla codigos_otp
    supabase.table("codigos_otp").insert({
        "usuario_id": current_user["id"],
        "codigo": codigo,
        "metodo": metodo,
        "expira_en": expira.isoformat(),
        "usado": False
    }).execute()
    
    # Enviar código por el método elegido
    if metodo == "email":
        enviar_correo(current_user["email"], "Código de verificación LUMIRE ERP", f"Tu código de verificación es: <b>{codigo}</b>")
    elif metodo == "sms":
        telefono = current_user.get("telefono")
        if not telefono:
            raise HTTPException(status_code=400, detail="No tienes un número de teléfono registrado")
        enviar_sms(telefono, f"Tu código de verificación LUMIRE ERP es: {codigo}")
    else:
        raise HTTPException(status_code=400, detail="Método no válido")
    
    return {"message": f"Código enviado por {metodo}"}

@app.post("/api/auth/confirm-2fa")
def confirm_2fa(codigo: str, current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    now = datetime.utcnow().isoformat()
    record = supabase.table("codigos_otp")\
        .select("*")\
        .eq("usuario_id", current_user["id"])\
        .eq("codigo", codigo)\
        .eq("usado", False)\
        .gte("expira_en", now)\
        .execute()
    
    if not record.data:
        raise HTTPException(status_code=400, detail="Código inválido o expirado")
    
    # Activar 2FA
    supabase.table("usuarios").update({
        "2fa_habilitado": True,
        "2fa_metodo": record.data[0]["metodo"],
        "ultima_verificacion_2fa": datetime.utcnow().isoformat()
    }).eq("id", current_user["id"]).execute()
    
    # Marcar código como usado
    supabase.table("codigos_otp").update({"usado": True}).eq("id", record.data[0]["id"]).execute()
    
    return {"message": "2FA activado correctamente"}

@app.post("/api/auth/disable-2fa")
def disable_2fa(current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    supabase.table("usuarios").update({
        "2fa_habilitado": False,
        "2fa_metodo": None
    }).eq("id", current_user["id"]).execute()
    
    return {"message": "2FA desactivado"}

@app.post("/api/auth/verify-2fa")
def verify_2fa(temporal_token: str, codigo: str):
    from database import get_supabase
    from auth import create_access_token
    supabase = get_supabase()
    
    # Validar temporal_token
    try:
        payload = jwt.decode(temporal_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not payload.get("temporal"):
            raise HTTPException(status_code=400, detail="Token inválido")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El tiempo para verificar ha expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Token inválido")
    
    # Buscar código OTP válido
    now = datetime.utcnow().isoformat()
    record = supabase.table("codigos_otp")\
        .select("*")\
        .eq("usuario_id", user_id)\
        .eq("codigo", codigo)\
        .eq("usado", False)\
        .gte("expira_en", now)\
        .execute()
    
    if not record.data:
        raise HTTPException(status_code=400, detail="Código inválido o expirado")
    
    # Marcar código como usado
    supabase.table("codigos_otp").update({"usado": True}).eq("id", record.data[0]["id"]).execute()
    
    # Actualizar última verificación
    supabase.table("usuarios").update({
        "ultima_verificacion_2fa": datetime.utcnow().isoformat()
    }).eq("id", user_id).execute()
    
    # Obtener usuario
    user = supabase.table("usuarios").select("*").eq("id", user_id).execute().data[0]
    
    # Generar token final
    access_token = create_access_token(data={
        "sub": str(user["id"]),
        "empresa_id": user["empresa_id"]
    })
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}