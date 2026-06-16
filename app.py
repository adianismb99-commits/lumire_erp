from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from auth import get_current_user, has_permission
from routes import productos, ventas, inventario, empleados, reportes

app = FastAPI(title="LUMIRE ERP API", version="1.0.0")

# CORS - configuracion completa
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://lumire-erp-frontend.onrender.com", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
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

@app.post("/api/login")
def login(usuario: dict):
    from auth import authenticate_user, create_access_token
    user = authenticate_user(usuario.get("email"), usuario.get("password"))
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    access_token = create_access_token(data={"sub": str(user["id"])})
    return {"access_token": access_token, "token_type": "bearer", "user": user}

from auth import get_password_hash

@app.get("/api/usuarios/")
def get_usuarios(current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    
    # Solo SUPER_ADMIN o GERENTE pueden ver usuarios
    if current_user["rol_id"] not in [1, 4]:  # 1=SUPER_ADMIN, 4=GERENTE
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    usuarios = supabase.table("usuarios").select("id, nombre, email, rol_id, activo").execute()
    return usuarios.data

@app.post("/api/usuarios/register")
def register_usuario(usuario: dict, current_user=Depends(get_current_user)):
    # Solo SUPER_ADMIN puede crear usuarios
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    from database import get_supabase
    supabase = get_supabase()
    
    # Hashear la contraseña
    hashed = get_password_hash(usuario.get("password"))
    
    # Crear usuario
    nuevo = supabase.table("usuarios").insert({
        "empresa_id": usuario.get("empresa_id", 1),
        "nombre": usuario.get("nombre"),
        "email": usuario.get("email"),
        "password_hash": hashed,
        "rol_id": usuario.get("rol_id")
    }).execute()
    
    return {"message": "Usuario creado", "id": nuevo.data[0]["id"]}

@app.get("/keepalive")
def keepalive():
    try:
        from database import get_supabase
        supabase = get_supabase()
        # Consulta mínima a la base de datos para mantenerla activa
        supabase.table("empresas").select("id").limit(1).execute()
        return {"status": "ok"}
    except Exception as e:
        print(f"Keepalive error: {e}")
        return {"status": "error", "detail": str(e)}, 500
    
@app.get("/api/usuarios/public")
def get_usuarios_public():
    from database import get_supabase
    supabase = get_supabase()
    
    # Solo devolver id, nombre, email (sin datos sensibles)
    usuarios = supabase.table("usuarios").select("id, nombre, email").execute()
    return usuarios.data

@app.put("/api/usuarios/{usuario_id}")
def update_usuario(usuario_id: int, usuario: dict, current_user=Depends(get_current_user)):
    # Solo SUPER_ADMIN puede editar
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    from database import get_supabase
    supabase = get_supabase()
    
    update_data = {
        "nombre": usuario.get("nombre"),
        "email": usuario.get("email"),
        "rol_id": usuario.get("rol_id")
    }
    
    # Si se envió contraseña, hashearla
    if usuario.get("password"):
        from auth import get_password_hash
        update_data["password_hash"] = get_password_hash(usuario.get("password"))
    
    result = supabase.table("usuarios").update(update_data).eq("id", usuario_id).execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return {"message": "Usuario actualizado"}

@app.delete("/api/usuarios/{usuario_id}")
def delete_usuario(usuario_id: int, current_user=Depends(get_current_user)):
    # Solo SUPER_ADMIN puede eliminar
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    # No permitir eliminar el propio usuario
    if usuario_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")
    
    from database import get_supabase
    supabase = get_supabase()
    
    result = supabase.table("usuarios").delete().eq("id", usuario_id).execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return {"message": "Usuario eliminado"}

@app.post("/api/usuarios/{usuario_id}/cambiar-pass")
def cambiar_password(usuario_id: int, data: dict, current_user=Depends(get_current_user)):
    from database import get_supabase
    from auth import verify_password, get_password_hash
    supabase = get_supabase()
    
    # Verificar que el usuario existe
    user = supabase.table("usuarios").select("*").eq("id", usuario_id).execute()
    if not user.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user_data = user.data[0]
    
    # Si es el mismo usuario, verificar contraseña actual
    if current_user["id"] == usuario_id:
        if not verify_password(data.get("pass_antigua"), user_data["password_hash"]):
            raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
    else:
        # Solo SUPER_ADMIN puede cambiar contraseña de otros sin verificar la actual
        if current_user["rol_id"] != 1:
            raise HTTPException(status_code=403, detail="Sin permiso")
    
    # Hashear y guardar nueva contraseña
    nueva_password = get_password_hash(data.get("pass_nueva"))
    supabase.table("usuarios").update({"password_hash": nueva_password}).eq("id", usuario_id).execute()
    
    return {"message": "Contraseña actualizada"}