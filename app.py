import os
import random
import string
import pyotp
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from auth import get_current_user, has_permission, authenticate_user, create_access_token, get_password_hash, verify_password
from routes import productos, ventas, inventario, empleados, reportes
from database import get_supabase
from notificaciones import enviar_correo

# ============================================
# CONFIGURACIÓN DE LA APP
# ============================================

app = FastAPI(title="LUMIRE ERP API", version="1.0.0")

# ============================================
# CORS
# ============================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lumire-erp-frontend.onrender.com",
        "https://lumire-erp-docker.onrender.com",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ============================================
# ROUTERS
# ============================================

app.include_router(productos.router, prefix="/api/productos", tags=["Productos"])
app.include_router(ventas.router, prefix="/api/ventas", tags=["Ventas"])
app.include_router(inventario.router, prefix="/api/inventario", tags=["Inventario"])
app.include_router(empleados.router, prefix="/api/empleados", tags=["Empleados"])
app.include_router(reportes.router, prefix="/api/reportes", tags=["Reportes"])

# ============================================
# ENDPOINTS BÁSICOS
# ============================================

@app.get("/")
def root():
    return {"message": "LUMIRE ERP API - Funcionando"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/keepalive")
def keepalive():
    try:
        supabase = get_supabase()
        supabase.table("empresas").select("id").limit(1).execute()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}, 500

# ============================================
# ENDPOINTS PÚBLICOS (Login, Empresas, Usuarios)
# ============================================

@app.get("/api/empresas")
def get_empresas():
    supabase = get_supabase()
    response = supabase.rpc("get_public_empresas", {}).execute()
    return response.data

@app.get("/api/usuarios/public")
def get_usuarios_public():
    supabase = get_supabase()
    response = supabase.rpc("get_public_users", {}).execute()
    usuarios_filtrados = [u for u in response.data if u.get("email") != "admin@lumire.com"]
    return usuarios_filtrados

@app.post("/api/login")
def login(usuario: dict):
    from auth import authenticate_user, create_access_token
    
    email = usuario.get("email")
    password = usuario.get("password")
    empresa_id = usuario.get("empresa_id")
    
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    if user["empresa_id"] != empresa_id:
        raise HTTPException(status_code=401, detail="Usuario no pertenece a esta empresa")
    
    # Verificar si tiene 2FA activado
    if user.get("2fa_habilitado"):
        # Generar token temporal (expira en 5 minutos)
        temp_token_data = {
            "sub": str(user["id"]),
            "temporal": True,
            "exp": datetime.utcnow() + timedelta(minutes=5)
        }
        temp_token = jwt.encode(temp_token_data, SECRET_KEY, algorithm=ALGORITHM)
        
        return {
            "requires_2fa": True,
            "temporal_token": temp_token,
            "message": "Se requiere verificación en dos pasos"
        }
    
    # Si no tiene 2FA, devolver token normal
    access_token = create_access_token(data={
        "sub": str(user["id"]),
        "empresa_id": empresa_id,
        "role": user["rol_id"]
    })
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}

# ============================================
# ENDPOINTS PARA USUARIOS
# ============================================

@app.get("/api/usuarios/")
def get_usuarios(current_user=Depends(get_current_user)):
    if current_user["rol_id"] not in [1, 4]:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    supabase = get_supabase()
    usuarios = supabase.table("usuarios")\
        .select("id, nombre, email, rol_id, activo")\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    
    return usuarios.data

@app.get("/api/usuarios/{usuario_id}")
def get_usuario(usuario_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    usuario = supabase.table("usuarios").select("*").eq("id", usuario_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not usuario.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return usuario.data[0]

@app.post("/api/usuarios/register")
def register_usuario(usuario: dict, current_user=Depends(get_current_user)):
    if current_user["rol_id"] != 1:
        raise HTTPException(status_code=403, detail="Sin permiso")
    
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
    
    supabase = get_supabase()
    update_data = {
        "nombre": usuario.get("nombre"),
        "email": usuario.get("email"),
        "rol_id": usuario.get("rol_id")
    }
    
    if usuario.get("password"):
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

@app.get("/api/usuarios/me")
def get_me(current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    usuario = supabase.table("usuarios").select("*").eq("id", current_user["id"]).eq("empresa_id", current_user["empresa_id"]).execute()
    if not usuario.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return usuario.data[0]

# ============================================
# ENDPOINTS PARA RECUPERACIÓN DE CONTRASEÑA
# ============================================

RECOVERY_SECRET = "otro-secreto-para-recuperacion"
RECOVERY_ALGORITHM = "HS256"
RECOVERY_EXPIRE_MINUTES = 60

@app.post("/api/auth/forgot-password")
def forgot_password(request: dict):
    email = request.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email es requerido")
    
    supabase = get_supabase()
    user = supabase.table("usuarios").select("id, email").eq("email", email).execute()
    if not user.data:
        return {"message": "Si el correo existe, recibirás un enlace para restablecer tu contraseña"}
    
    user_id = user.data[0]["id"]
    token_data = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=RECOVERY_EXPIRE_MINUTES)
    }
    token = jwt.encode(token_data, RECOVERY_SECRET, algorithm=RECOVERY_ALGORITHM)
    
    supabase.table("tokens_recuperacion").insert({
        "usuario_id": user_id,
        "token": token,
        "expira_en": (datetime.utcnow() + timedelta(minutes=RECOVERY_EXPIRE_MINUTES)).isoformat()
    }).execute()
    
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
    
    token_record = supabase.table("tokens_recuperacion").select("*").eq("token", token).eq("usado", False).execute()
    if not token_record.data:
        raise HTTPException(status_code=400, detail="Token ya usado o inválido")
    
    hashed = get_password_hash(new_password)
    supabase.table("usuarios").update({"password_hash": hashed}).eq("id", user_id).execute()
    supabase.table("tokens_recuperacion").update({"usado": True}).eq("token", token).execute()
    
    return {"message": "Contraseña actualizada correctamente"}

# ============================================
# ENDPOINTS PARA RECETAS Y PRODUCCIÓN
# ============================================

@app.get("/api/recetas/")
def get_recetas(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    recetas = supabase.table("recetas").select("*").execute()
    return recetas.data

@app.get("/api/recetas/{receta_id}/ingredientes")
def get_receta_ingredientes(receta_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    detalles = supabase.table("recetas_detalle").select("*, ingredientes(*)").eq("receta_id", receta_id).execute()
    return detalles.data

@app.get("/api/recetas/{receta_id}/calcular")
def calcular_produccion(receta_id: int, cantidad: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    detalles = supabase.table("recetas_detalle").select("*, ingredientes(*)").eq("receta_id", receta_id).execute()
    if not detalles.data:
        return {"error": "No se encontraron ingredientes"}
    
    resultado = []
    for detalle in detalles.data:
        ing = detalle.get("ingredientes", {})
        resultado.append({
            "ingrediente_id": detalle["ingrediente_id"],
            "ingrediente_nombre": ing.get("nombre", "Desconocido"),
            "cantidad_por_unidad": detalle["cantidad"],
            "unidad": detalle.get("unidad", "unidad"),
            "cantidad_total": detalle["cantidad"] * cantidad
        })
    
    return resultado

@app.post("/api/produccion/")
def registrar_produccion(data: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    receta_id = data.get("receta_id")
    cantidad = data.get("cantidad_producir")
    lote = data.get("lote")
    fecha = data.get("fecha")
    
    if not receta_id or not cantidad or not lote:
        raise HTTPException(status_code=400, detail="Faltan datos")
    
    detalles = supabase.table("recetas_detalle").select("*, ingredientes(*)").eq("receta_id", receta_id).execute()
    
    supabase.table("produccion").insert({
        "receta_id": receta_id,
        "cantidad_teorica": cantidad,
        "cantidad_real": cantidad,
        "lote": lote,
        "fecha_produccion": fecha or datetime.now().isoformat(),
        "estado": "completada"
    }).execute()
    
    for detalle in detalles.data:
        ing_id = detalle["ingrediente_id"]
        cantidad_necesaria = detalle["cantidad"] * cantidad
        stock = supabase.table("inventario").select("cantidad").eq("ingrediente_id", ing_id).execute()
        if stock.data:
            stock_actual = stock.data[0]["cantidad"]
            nuevo_stock = stock_actual - cantidad_necesaria
            supabase.table("inventario").update({"cantidad": nuevo_stock}).eq("ingrediente_id", ing_id).execute()
    
    return {"message": "Producción registrada", "lote": lote}

# ============================================
# ENDPOINTS PARA INVENTARIO
# ============================================

@app.get("/api/ingredientes/")
def get_ingredientes(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    ingredientes = supabase.table("ingredientes").select("*").execute()
    return ingredientes.data

@app.post("/api/ingredientes/")
def create_ingrediente(ingrediente: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    nuevo = supabase.table("ingredientes").insert({
        "nombre": ingrediente.get("nombre"),
        "unidad": ingrediente.get("unidad", "unidad"),
        "stock_minimo": ingrediente.get("stock_minimo", 0),
        "stock_actual": ingrediente.get("stock_actual", 0),
        "empresa_id": current_user["empresa_id"]
    }).execute()
    return nuevo.data[0]

@app.put("/api/ingredientes/{ingrediente_id}")
def update_ingrediente(ingrediente_id: int, ingrediente: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    updated = supabase.table("ingredientes").update({
        "nombre": ingrediente.get("nombre"),
        "unidad": ingrediente.get("unidad", "unidad"),
        "stock_minimo": ingrediente.get("stock_minimo", 0),
        "stock_actual": ingrediente.get("stock_actual", 0)
    }).eq("id", ingrediente_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not updated.data:
        raise HTTPException(status_code=404, detail="Ingrediente no encontrado")
    return updated.data[0]

@app.delete("/api/ingredientes/{ingrediente_id}")
def delete_ingrediente(ingrediente_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    result = supabase.table("ingredientes").delete().eq("id", ingrediente_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Ingrediente no encontrado")
    return {"message": "Ingrediente eliminado"}

@app.post("/api/inventario/comprar")
def registrar_compra(data: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    ingrediente_id = data.get("ingrediente_id")
    cantidad = data.get("cantidad")
    costo = data.get("costo", 0)
    
    if not ingrediente_id or not cantidad:
        raise HTTPException(status_code=400, detail="Faltan datos")
    
    ingrediente = supabase.table("ingredientes").select("stock_actual").eq("id", ingrediente_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not ingrediente.data:
        raise HTTPException(status_code=404, detail="Ingrediente no encontrado")
    
    nuevo_stock = ingrediente.data[0]["stock_actual"] + cantidad
    supabase.table("ingredientes").update({"stock_actual": nuevo_stock}).eq("id", ingrediente_id).execute()
    
    supabase.table("movimientos_inventario").insert({
        "ingrediente_id": ingrediente_id,
        "tipo": "compra",
        "cantidad": cantidad,
        "costo": costo,
        "empresa_id": current_user["empresa_id"]
    }).execute()
    
    return {"message": "Compra registrada", "nuevo_stock": nuevo_stock}

@app.post("/api/inventario/ajustar")
def ajustar_stock(data: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    ingrediente_id = data.get("ingrediente_id")
    nueva_cantidad = data.get("nueva_cantidad")
    motivo = data.get("motivo", "Ajuste manual")
    
    if not ingrediente_id or nueva_cantidad is None:
        raise HTTPException(status_code=400, detail="Faltan datos")
    
    ingrediente = supabase.table("ingredientes").select("stock_actual").eq("id", ingrediente_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not ingrediente.data:
        raise HTTPException(status_code=404, detail="Ingrediente no encontrado")
    
    stock_actual = ingrediente.data[0]["stock_actual"]
    diferencia = nueva_cantidad - stock_actual
    tipo = "ajuste_positivo" if diferencia > 0 else "ajuste_negativo"
    
    supabase.table("ingredientes").update({"stock_actual": nueva_cantidad}).eq("id", ingrediente_id).execute()
    
    supabase.table("movimientos_inventario").insert({
        "ingrediente_id": ingrediente_id,
        "tipo": tipo,
        "cantidad": abs(diferencia),
        "motivo": motivo,
        "empresa_id": current_user["empresa_id"]
    }).execute()
    
    return {"message": "Stock ajustado", "nuevo_stock": nueva_cantidad}

@app.get("/api/inventario/historial/{ingrediente_id}")
def get_historial(ingrediente_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    movimientos = supabase.table("movimientos_inventario").select("*").eq("ingrediente_id", ingrediente_id).eq("empresa_id", current_user["empresa_id"]).order("fecha", desc=True).execute()
    return movimientos.data

# ============================================
# ENDPOINTS PARA NÓMINA
# ============================================

@app.get("/api/empleados/")
def get_empleados(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    empleados = supabase.table("empleados").select("*").eq("empresa_id", current_user["empresa_id"]).execute()
    return empleados.data

@app.post("/api/empleados/")
def create_empleado(empleado: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    # Datos obligatorios
    nombre = empleado.get("nombre")
    email = empleado.get("email")
    tipo = empleado.get("tipo", "Empleado")
    salario_base = empleado.get("salario_base", 0)
    comision_porcentaje = empleado.get("comision_porcentaje", 0)
    fecha_ingreso = empleado.get("fecha_ingreso")
    crear_usuario = empleado.get("crear_usuario", True)
    
    # Obtener empresa_id del usuario autenticado
    empresa_id = current_user["empresa_id"]
    
    # Insertar empleado
    nuevo_empleado = supabase.table("empleados").insert({
        "nombre": nombre,
        "email": email,
        "tipo": tipo,
        "salario_base": salario_base,
        "comision_porcentaje": comision_porcentaje,
        "fecha_ingreso": fecha_ingreso,
        "empresa_id": empresa_id  # <--- Asegurar que este campo existe
    }).execute()
        
    empleado_id = nuevo_empleado.data[0]["id"]
    resultado = {"empleado_id": empleado_id, "usuario_creado": False}
    
    if crear_usuario:
        caracteres = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(caracteres) for _ in range(10))
        hashed = get_password_hash(password)
        
        existing = supabase.table("usuarios").select("id").eq("email", email).execute()
        if existing.data:
            resultado["usuario_creado"] = False
            resultado["error"] = "El email ya está registrado"
        else:
            nuevo_usuario = supabase.table("usuarios").insert({
                "empresa_id": empresa_id,
                "nombre": nombre,
                "email": email,
                "password_hash": hashed,
                "rol_id": 2,
                "activo": True
            }).execute()
            
            supabase.table("empleados").update({
                "usuario_id": nuevo_usuario.data[0]["id"]
            }).eq("id", empleado_id).execute()
            
            resultado["usuario_creado"] = True
            resultado["usuario_id"] = nuevo_usuario.data[0]["id"]
            resultado["usuario_email"] = email
            resultado["usuario_password"] = password
    
    return resultado

@app.put("/api/empleados/{empleado_id}")
def update_empleado(empleado_id: int, empleado: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    updated = supabase.table("empleados").update({
        "nombre": empleado.get("nombre"),
        "email": empleado.get("email"),
        "tipo": empleado.get("tipo", "Empleado"),
        "salario_base": empleado.get("salario_base", 0),
        "comision_porcentaje": empleado.get("comision_porcentaje", 0),
        "fecha_ingreso": empleado.get("fecha_ingreso")
    }).eq("id", empleado_id).eq("empresa_id", current_user["empresa_id"]).execute()
    
    if not updated.data:
        raise HTTPException(status_code=404, detail="Empleado no encontrado")
    
    return updated.data[0]

@app.delete("/api/empleados/{empleado_id}")
def delete_empleado(empleado_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    empleado = supabase.table("empleados").select("usuario_id").eq("id", empleado_id).eq("empresa_id", current_user["empresa_id"]).execute()
    
    result = supabase.table("empleados").delete().eq("id", empleado_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Empleado no encontrado")
    
    if empleado.data and empleado.data[0].get("usuario_id"):
        supabase.table("usuarios").delete().eq("id", empleado.data[0]["usuario_id"]).eq("empresa_id", current_user["empresa_id"]).execute()
    
    return {"message": "Empleado y usuario eliminado"}

# ============================================
# ENDPOINTS PARA ASISTENCIAS
# ============================================

@app.post("/api/asistencias/")
def create_asistencia(data: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    empleado_id = data.get("empleado_id")
    fecha = data.get("fecha")
    hora_entrada = data.get("hora_entrada")
    hora_salida = data.get("hora_salida")
    
    if not empleado_id or not fecha or not hora_entrada or not hora_salida:
        raise HTTPException(status_code=400, detail="Faltan datos")
    
    h1 = datetime.strptime(hora_entrada, "%H:%M")
    h2 = datetime.strptime(hora_salida, "%H:%M")
    horas = (h2 - h1).seconds / 3600
    
    nueva = supabase.table("asistencias").insert({
        "empleado_id": empleado_id,
        "fecha": fecha,
        "hora_entrada": hora_entrada,
        "hora_salida": hora_salida,
        "horas_trabajadas": round(horas, 2)
    }).execute()
    return nueva.data[0]

@app.get("/api/asistencias/")
def get_asistencias(fecha: str, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    asistencias = supabase.table("asistencias").select("*, empleados(nombre)").eq("fecha", fecha).execute()
    
    resultado = []
    for a in asistencias.data:
        emp = a.get("empleados", {})
        resultado.append({
            "id": a.get("id"),
            "empleado_id": a.get("empleado_id"),
            "empleado_nombre": emp.get("nombre") if emp else None,
            "fecha": a.get("fecha"),
            "hora_entrada": a.get("hora_entrada"),
            "hora_salida": a.get("hora_salida"),
            "horas_trabajadas": a.get("horas_trabajadas")
        })
    return resultado

# ============================================
# ENDPOINTS PARA NÓMINA (cálculo e historial)
# ============================================

@app.get("/api/nomina/calcular")
def calcular_nomina(empleado_id: int, mes: str, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    empleado = supabase.table("empleados").select("*").eq("id", empleado_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not empleado.data:
        return {"error": "Empleado no encontrado"}
    
    emp = empleado.data[0]
    salario_base = emp.get("salario_base", 0)
    comision_porcentaje = emp.get("comision_porcentaje", 0)
    
    asistencias = supabase.table("asistencias").select("*").eq("empleado_id", empleado_id).like("fecha", f"{mes}%").execute()
    
    horas_totales = sum(a.get("horas_trabajadas", 0) for a in asistencias.data)
    dias_trabajados = len(asistencias.data)
    
    valor_hora = salario_base / 176 if salario_base > 0 else 0
    salario_devengado = horas_totales * valor_hora
    
    comisiones = salario_devengado * (comision_porcentaje / 100) if comision_porcentaje > 0 else 0
    bonos = 0
    deducciones = 0
    
    total = salario_devengado + comisiones + bonos - deducciones
    
    return {
        "empleado_id": empleado_id,
        "mes": mes,
        "salario_base": round(salario_base, 2),
        "salario_devengado": round(salario_devengado, 2),
        "comisiones": round(comisiones, 2),
        "bonos": round(bonos, 2),
        "deducciones": round(deducciones, 2),
        "total": round(total, 2),
        "horas_trabajadas": round(horas_totales, 2),
        "dias_trabajados": dias_trabajados
    }

@app.get("/api/nomina/historial")
def get_nomina_historial(mes: str, current_user=Depends(get_current_user)):
    from database import get_supabase
    supabase = get_supabase()
    # Por ahora, devolvemos datos simulados
    return []

# ============================================
# ENDPOINTS PARA 2FA (Google Authenticator)
# ============================================

@app.post("/api/auth/enable-2fa")
def enable_2fa(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    # Generar clave secreta si no existe
    secret = current_user.get("secret_2fa")
    if not secret:
        secret = pyotp.random_base32()
        supabase.table("usuarios").update({
            "secret_2fa": secret
        }).eq("id", current_user["id"]).execute()
    
    # Generar URL para el QR
    totp = pyotp.TOTP(secret)
    nombre_usuario = current_user.get("email", "usuario@lumire.com")
    qr_url = totp.provisioning_uri(nombre_usuario, issuer_name="LUMIRE ERP")
    
    # Generar código QR en base64 (para mostrar en el frontend)
    qr = qrcode.make(qr_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return {
        "secret": secret,
        "qr_base64": qr_base64,
        "qr_url": qr_url
    }

@app.post("/api/auth/confirm-2fa")
def confirm_2fa(data: dict, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    codigo = data.get("codigo")
    if not codigo:
        raise HTTPException(status_code=400, detail="Código requerido")
    
    secret = current_user.get("secret_2fa")
    if not secret:
        raise HTTPException(status_code=400, detail="No hay clave secreta configurada")
    
    # Verificar el código
    totp = pyotp.TOTP(secret)
    if not totp.verify(codigo):
        raise HTTPException(status_code=400, detail="Código inválido")
    
    # Activar 2FA
    supabase.table("usuarios").update({
        "2fa_habilitado": True,
        "ultima_verificacion_2fa": datetime.utcnow().isoformat()
    }).eq("id", current_user["id"]).execute()
    
    return {"message": "2FA activado correctamente"}

@app.post("/api/auth/disable-2fa")
def disable_2fa(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    
    supabase.table("usuarios").update({
        "2fa_habilitado": False,
        "secret_2fa": None,
        "ultima_verificacion_2fa": None
    }).eq("id", current_user["id"]).execute()
    
    return {"message": "2FA desactivado"}

@app.post("/api/auth/verify-2fa")
def verify_2fa(data: dict):
    supabase = get_supabase()
    from auth import create_access_token
    
    temporal_token = data.get("temporal_token")
    codigo = data.get("codigo")
    
    if not temporal_token or not codigo:
        raise HTTPException(status_code=400, detail="Faltan datos")
    
    # Validar el temporal_token (contiene user_id)
    try:
        payload = jwt.decode(temporal_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not payload.get("temporal"):
            raise HTTPException(status_code=400, detail="Token inválido")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El tiempo para verificar ha expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Token inválido")
    
    # Obtener usuario
    user = supabase.table("usuarios").select("*").eq("id", user_id).execute()
    if not user.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user_data = user.data[0]
    
    # Verificar el código
    secret = user_data.get("secret_2fa")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA no configurado para este usuario")
    
    totp = pyotp.TOTP(secret)
    if not totp.verify(codigo):
        raise HTTPException(status_code=400, detail="Código inválido")
    
    # Actualizar última verificación
    supabase.table("usuarios").update({
        "ultima_verificacion_2fa": datetime.utcnow().isoformat()
    }).eq("id", user_id).execute()
    
    # Generar token final
    access_token = create_access_token(data={
        "sub": str(user_data["id"]),
        "empresa_id": user_data["empresa_id"],
        "role": user_data["rol_id"]
    })
    
    return {"access_token": access_token, "token_type": "bearer", "user": user_data}