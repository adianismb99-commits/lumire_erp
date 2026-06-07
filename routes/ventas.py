from fastapi import APIRouter, Depends, HTTPException
from database import get_supabase
from auth import get_current_user, has_permission
from models import VentaCreate

router = APIRouter()

@router.get("/")
def get_ventas(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    ventas = supabase.table("ventas").select("*").execute()
    return ventas.data

@router.post("/")
def create_venta(venta: VentaCreate, current_user=Depends(get_current_user)):
    if not has_permission(current_user, "ventas", "crear"):
        raise HTTPException(status_code=403, detail="Sin permiso")
    supabase = get_supabase()
    total = sum(d.cantidad * d.precio_unitario for d in venta.detalles)
    nueva_venta = supabase.table("ventas").insert({
        "sesion_caja_id": venta.sesion_caja_id,
        "cliente_nombre": venta.cliente_nombre,
        "metodo_pago": venta.metodo_pago,
        "total": total,
        "estado": "completada"
    }).execute()
    venta_id = nueva_venta.data[0]["id"]
    for detalle in venta.detalles:
        supabase.table("ventas_detalle").insert({
            "venta_id": venta_id,
            "producto_id": detalle.producto_id,
            "cantidad": detalle.cantidad,
            "precio_unitario": detalle.precio_unitario,
            "subtotal": detalle.cantidad * detalle.precio_unitario
        }).execute()
    return nueva_venta.data[0]