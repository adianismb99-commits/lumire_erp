import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# Estas variables las configuras en Render
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL")

def enviar_correo(destinatario: str, asunto: str, cuerpo_html: str):
    """
    Envía un correo usando SMTP.
    Retorna True si se envió correctamente, False en caso contrario.
    """
    # Verificar que todo está configurado
    if not SMTP_USER or not SMTP_PASS:
        print("Error: Credenciales SMTP no configuradas")
        return False

    if not FROM_EMAIL:
        print("Error: FROM_EMAIL no configurado")
        return False

    try:
        # Crear el mensaje
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = destinatario
        msg['Subject'] = asunto
        msg.attach(MIMEText(cuerpo_html, 'html'))

        # Conectar al servidor SMTP y enviar
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()  # Activar seguridad
        server.login(SMTP_USER, SMTP_PASS)  # Iniciar sesión
        server.send_message(msg)  # Enviar correo
        server.quit()  # Cerrar conexión
        
        print(f"Correo enviado a {destinatario}")
        return True

    except Exception as e:
        print(f"Error enviando correo: {e}")
        return False