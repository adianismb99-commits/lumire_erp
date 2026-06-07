from fastapi import APIRouter, Depends, HTTPException
from database import get_supabase
from auth import get_current_user, has_permission
from models import ProductoCreate, ProductoResponse

router = APIRouter()

@router.get("/")
def get_productos(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    productos = supabase.table("productos").select("*").eq("empresa_id", current_user["empresa_id"]).execute()
    return productos.data

@router.get("/{producto_id}")
def get_producto(producto_id: int, current_user=Depends(get_current_user)):
    supabase = get_supabase()
    producto = supabase.table("productos").select("*").eq("id", producto_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not producto.data:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    return producto.data[0]

@router.post("/")
def create_producto(producto: ProductoCreate, current_user=Depends(get_current_user)):
    if not has_permission(current_user, "productos", "crear"):
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    supabase = get_supabase()
    new_producto = supabase.table("productos").insert({
        **producto.dict(),
        "empresa_id": current_user["empresa_id"]
    }).execute()
    return new_producto.data[0]

@router.put("/{producto_id}")
def update_producto(producto_id: int, producto: dict, current_user=Depends(get_current_user)):
    if not has_permission(current_user, "productos", "actualizar"):
        raise HTTPException(status_code=403, detail="Sin permiso")
    
    supabase = get_supabase()
    updated = supabase.table("productos").update(producto).eq("id", producto_id).eq("empresa_id", current_user["empresa_id"]).execute()
    if not updated.data:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    return updated.data[0]