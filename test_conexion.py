import os
from dotenv import load_dotenv
from supabase import create_client

env_path = r"C:\Users\adian\Desktop\LUMIRE_ERP\backend\.env"
load_dotenv(dotenv_path=env_path, override=True)

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_ANON_KEY")

print("URL:", url)
print("KEY:", key[:30] if key else "No key")

if not url or not key:
    print("ERROR: Faltan variables")
    exit()

try:
    supabase = create_client(url, key)
    respuesta = supabase.table("empresas").select("*").limit(1).execute()
    print("\n✅ CONEXION EXITOSA")
    print("Respuesta:", respuesta.data)
except Exception as e:
    print("\n❌ ERROR:", e)