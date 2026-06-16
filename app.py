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
    usuarios = supabase.table("usuarios").select("id, nombre, email, rol_id, empresa_id").execute()
    usuarios_filtrados = [u for u in usuarios.data if u.get("email") != "admin@lumire.com"]
    return usuarios_filtrados

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