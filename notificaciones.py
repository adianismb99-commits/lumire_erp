# notificaciones.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# Configuración SMTP
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

# Twilio (opcional)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

def enviar_correo(destinatario: str, asunto: str, cuerpo: str):
    try:
        if not SMTP_USER or not SMTP_PASS:
            print("Error: SMTP_USER o SMTP_PASS no configurados")
            return False
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = destinatario
        msg['Subject'] = asunto
        msg.attach(MIMEText(cuerpo, 'html'))
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        print(f"Correo enviado a {destinatario}")
        return True
    except Exception as e:
        print(f"Error enviando correo: {e}")
        return False

def enviar_sms(destinatario: str, mensaje: str):
    try:
        if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
            print("Error: Twilio no configurado")
            return False
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=mensaje,
            from_=TWILIO_PHONE_NUMBER,
            to=destinatario
        )
        print(f"SMS enviado a {destinatario}")
        return True
    except Exception as e:
        print(f"Error enviando SMS: {e}")
        return False