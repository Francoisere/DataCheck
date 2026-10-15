"""
Servidor FastAPI principal para DataCheck.cl.
Configuración de middlewares, ciclo de vida (lifespan) y montaje estático.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.api.routes import scan, health, reports, flow
from src.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializar tablas en base de datos al arrancar
    await init_db()
    yield
    # Limpieza al apagar si fuera necesario


app = FastAPI(
    title="DataCheck.cl - Plataforma de Auditoría de Cumplimiento de Datos Personales (Chile)",
    description=(
        "API REST asíncrona de escaneo pasivo y evaluación normativa determinista "
        "para la Ley N° 19.628 y Nueva Ley de Protección de Datos Personales de Chile."
    ),
    version="2.0.0",
    lifespan=lifespan
)

# CORS abierto para soportar Bookmarklet y pruebas desde cualquier origen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registrar routers modulares
app.include_router(scan.router)
app.include_router(health.router)
app.include_router(reports.router)
app.include_router(flow.router)

# Montar interfaz web estática en la raíz "/"
ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui")
if os.path.exists(ui_dir):
    app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
