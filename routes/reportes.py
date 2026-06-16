from fastapi import APIRouter, Depends
from database import get_supabase
from auth import get_current_user

router = APIRouter()

@router.get("/ventas")
def reporte_ventas(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    ventas = supabase.table("ventas")\
        .select("*")\
        .eq("empresa_id", current_user["empresa_id"])\
        .execute()
    total = sum(v["total"] for v in ventas.data)
    return {"total_ventas": total, "cantidad": len(ventas.data)}