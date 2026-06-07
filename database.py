import os
from supabase import create_client, Client

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_ANON_KEY")

print(f"URL desde entorno: {url}")

if not url or not key:
    raise Exception("Faltan variables de entorno")

supabase: Client = create_client(url, key)

def get_supabase():
    return supabase