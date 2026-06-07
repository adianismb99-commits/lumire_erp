from fastapi import APIRouter, Depends
from database import get_supabase
from auth import get_current_user

router = APIRouter()

@router.get("/")
def get_inventario(current_user=Depends(get_current_user)):
    supabase = get_supabase()
    inventario = supabase.table("inventario").select("*, productos(*)").execute()
    return inventario.data