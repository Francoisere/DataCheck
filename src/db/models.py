"""
Modelos de Datos Relacionales (SQLAlchemy 2.0).
Esquema Relacional Inmutable definido en implementation_plan_increment2.md:
- sitios_analizados
- auditorias
- resultados_pilares
- hallazgos
- evidencias_rastreadores
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    String,
    Integer,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from src.db.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SitioAnalizado(Base):
    __tablename__ = "sitios_analizados"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    url_normalizada: Mapped[str] = mapped_column(String(500), unique=True, index=True, nullable=False)
    dominio: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relaciones
    auditorias: Mapped[List["Auditoria"]] = relationship(
        "Auditoria", back_populates="sitio", cascade="all, delete-orphan"
    )


class Auditoria(Base):
    __tablename__ = "auditorias"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sitio_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sitios_analizados.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ejecutada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    page_load_status: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)  # APROBADO | CON_OBSERVACIONES | RECHAZADO
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    duracion_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resumen: Mapped[str] = mapped_column(Text, nullable=False)

    # Relaciones
    sitio: Mapped["SitioAnalizado"] = relationship("SitioAnalizado", back_populates="auditorias")
    resultados_pilares: Mapped[List["ResultadoPilar"]] = relationship(
        "ResultadoPilar", back_populates="auditoria", cascade="all, delete-orphan"
    )
    evidencias_rastreadores: Mapped[List["EvidenciaRastreador"]] = relationship(
        "EvidenciaRastreador", back_populates="auditoria", cascade="all, delete-orphan"
    )


class ResultadoPilar(Base):
    __tablename__ = "resultados_pilares"
    __table_args__ = (
        UniqueConstraint("auditoria_id", "pilar", name="uq_auditoria_pilar"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    auditoria_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auditorias.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pilar: Mapped[str] = mapped_column(String(50), nullable=False)  # POLITICA_PRIVACIDAD | CANALES_ARCO | CONSENTIMIENTO_COOKIES
    estado: Mapped[str] = mapped_column(String(30), nullable=False)  # CUMPLE | OBSERVACION | FALLA
    puntaje: Mapped[int] = mapped_column(Integer, nullable=False)
    puntaje_max: Mapped[int] = mapped_column(Integer, nullable=False)

    # Relaciones
    auditoria: Mapped["Auditoria"] = relationship("Auditoria", back_populates="resultados_pilares")
    hallazgos: Mapped[List["Hallazgo"]] = relationship(
        "Hallazgo", back_populates="resultado_pilar", cascade="all, delete-orphan"
    )


class Hallazgo(Base):
    __tablename__ = "hallazgos"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    resultado_pilar_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resultados_pilares.id", ondelete="CASCADE"), nullable=False, index=True
    )
    severidad: Mapped[str] = mapped_column(String(20), nullable=False)  # OK | WARNING | FAIL
    titulo: Mapped[str] = mapped_column(String(255), nullable=False)
    detalle: Mapped[str] = mapped_column(String(300), nullable=False)  # Privacy by Design max 300 chars
    technical_raw: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    recomendacion: Mapped[str] = mapped_column(Text, nullable=False)

    # Relaciones
    resultado_pilar: Mapped["ResultadoPilar"] = relationship("ResultadoPilar", back_populates="hallazgos")


class EvidenciaRastreador(Base):
    __tablename__ = "evidencias_rastreadores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    auditoria_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auditorias.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tipo: Mapped[str] = mapped_column(String(20), nullable=False)  # DOMINIO | COOKIE
    valor: Mapped[str] = mapped_column(String(255), nullable=False)
    categoria: Mapped[str] = mapped_column(String(50), default="TRACKER", nullable=False)

    # Relaciones
    auditoria: Mapped["Auditoria"] = relationship("Auditoria", back_populates="evidencias_rastreadores")


class EtapaFlujo(Base):
    """Registro de una etapa individual en un flujo de compra/registro auditado."""
    __tablename__ = "etapas_flujo"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    auditoria_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auditorias.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    nombre_etapa: Mapped[str] = mapped_column(String(50), nullable=False)
    etiqueta: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    orden: Mapped[int] = mapped_column(Integer, nullable=False)
    veredicto: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # CUMPLE | NO_CUMPLE | NO_VERIFICABLE | NO_ALCANZADA
    http_status: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requests_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relaciones
    auditoria: Mapped["Auditoria"] = relationship("Auditoria", backref="etapas_flujo")
    evidencias: Mapped[List["EvidenciaEtapa"]] = relationship(
        "EvidenciaEtapa", back_populates="etapa", cascade="all, delete-orphan"
    )


class EvidenciaEtapa(Base):
    """Evidencia de rastreo encontrada en una etapa del flujo (dominio o cookie nueva)."""
    __tablename__ = "evidencias_etapa"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    etapa_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("etapas_flujo.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    tipo: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # DOMINIO_NUEVO | COOKIE_NUEVA
    valor: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # Solo nombre de dominio o cookie, nunca valores (DA-04)
    es_nuevo_en_etapa: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Relaciones
    etapa: Mapped["EtapaFlujo"] = relationship("EtapaFlujo", back_populates="evidencias")


class AuditoriaProgramada(Base):
    __tablename__ = "auditorias_programadas"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sitio_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sitios_analizados.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ultima_auditoria_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auditorias.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email_notificacion: Mapped[str] = mapped_column(String(255), nullable=False)
    intervalo_tipo: Mapped[str] = mapped_column(String(50), nullable=False)  # DEMO_2_MIN | PROD_15_DAYS
    proxima_ejecucion_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    estado: Mapped[str] = mapped_column(String(30), default="PENDIENTE", nullable=False, index=True)  # PENDIENTE | PROCESANDO | COMPLETADA | FALLIDA | CANCELADA
    reintentos: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    ejecutado_en: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    nueva_auditoria_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auditorias.id", ondelete="SET NULL"), nullable=True
    )

    # Relaciones
    sitio: Mapped["SitioAnalizado"] = relationship("SitioAnalizado")
    ultima_auditoria: Mapped["Auditoria"] = relationship("Auditoria", foreign_keys=[ultima_auditoria_id])
    nueva_auditoria: Mapped[Optional["Auditoria"]] = relationship("Auditoria", foreign_keys=[nueva_auditoria_id])

