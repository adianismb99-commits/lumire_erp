from fastapi import APIRouter, Depends
from database import get_supabase
from auth import get_current_user

router = APIRouter()

@router.get("/")
def get_empleados(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    empleados = supabase.table("empleados").select("*").eq("empresa_id", current_user["empresa_id"]).execute()
    return empleados.data