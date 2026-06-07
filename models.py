from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Modelos de Productos
class ProductoBase(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    precio_venta: float
    precio_compra: Optional[float] = None
    unidad_base: str
    impuesto: float = 0
    activo: bool = True

class ProductoCreate(ProductoBase):
    empresa_id: int
    categoria_id: Optional[int] = None

class ProductoResponse(ProductoBase):
    id: int
    empresa_id: int
    created_at: datetime

# Modelos de Ventas
class VentaDetalle(BaseModel):
    producto_id: int
    cantidad: float
    precio_unitario: float

class VentaCreate(BaseModel):
    sesion_caja_id: int
    cliente_nombre: str
    metodo_pago: str
    detalles: list[VentaDetalle]

class VentaResponse(BaseModel):
    id: int
    total: float
    fecha: datetime
    estado: str

# Modelos de Usuario y Autenticación
class UsuarioCreate(BaseModel):
    nombre: str
    email: str
    password: str
    empresa_id: int
    rol_id: int

class UsuarioLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str