import os
from supabase import create_client, Client

# Leer el .env directamente sin load_dotenv
env_path = r"C:\Users\adian\Desktop\LUMIRE_ERP\backend\.env"

url = None
key = None

with open(env_path, 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('SUPABASE_URL='):
            url = line.split('=', 1)[1]
        elif line.startswith('SUPABASE_ANON_KEY='):
            key = line.split('=', 1)[1]

print(f"URL leída manualmente: {url}")
print(f"KEY leída manualmente: {key[:50] if key else 'No key'}...")

if not url or not key:
    raise Exception("No se pudieron leer las variables")

supabase: Client = create_client(url, key)

def get_supabase():
    return supabase