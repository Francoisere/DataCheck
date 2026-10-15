"""
Patrones de descubrimiento de etapas de flujo de compra/registro.
Usado por FlowInspector para identificar enlaces de navegación secuencial
dentro del mismo dominio (Nivel 0: solo lectura, solo GET públicos).
"""

from typing import List, Dict

# Etapas del flujo de compra/registro, en orden secuencial.
# Cada etapa tiene un nombre, patrones de URL (paths), y patrones de texto
# en el anchor text del enlace.
FLOW_STAGES = [
    {
        "name": "catalogo",
        "label": "Catálogo / Productos",
        "url_patterns": [
            "/productos", "/products", "/catalogo", "/catalog",
            "/tienda", "/shop", "/store", "/coleccion", "/collection",
            "/categoria", "/category", "/ofertas", "/deals",
        ],
        "text_patterns": [
            "productos", "tienda", "shop", "catálogo", "catalogo",
            "ver productos", "comprar", "ofertas", "novedades",
        ],
    },
    {
        "name": "registro",
        "label": "Registro / Crear Cuenta",
        "url_patterns": [
            "/registro", "/register", "/crear-cuenta", "/create-account",
            "/signup", "/sign-up", "/nueva-cuenta", "/join",
            "/mi-cuenta", "/my-account", "/account", "/cuenta",
            "/login", "/iniciar-sesion",
        ],
        "text_patterns": [
            "registrarse", "crear cuenta", "register", "sign up",
            "nueva cuenta", "iniciar sesión", "login", "mi cuenta",
            "unirse", "regístrate",
        ],
    },
    {
        "name": "carrito",
        "label": "Carrito / Checkout",
        "url_patterns": [
            "/carrito", "/cart", "/checkout", "/carro",
            "/basket", "/bag", "/order", "/pedido",
            "/finalizar-compra", "/pagar",
        ],
        "text_patterns": [
            "carrito", "cart", "checkout", "ver carrito",
            "finalizar compra", "pagar", "mi pedido",
            "carro de compras", "bolsa",
        ],
    },
]

# Dominios de pasarelas de pago externas.
# Si un enlace descubierto apunta a uno de estos dominios, la etapa se marca
# como "no alcanzada: pasarela externa" y el recorrido se detiene.
PAYMENT_GATEWAY_DOMAINS = [
    # Chile
    "webpay.transbank.cl",
    "www.webpay.cl",
    "app.flow.cl",
    "www.flow.cl",
    "www.khipu.com",
    # Internacionales
    "www.mercadopago.cl",
    "www.mercadopago.com",
    "checkout.mercadopago.com",
    "www.paypal.com",
    "checkout.stripe.com",
    "pay.stripe.com",
    "checkout.shopify.com",
    "secure.2checkout.com",
    "pay.dlocal.com",
    "checkout.payulatam.com",
    "secure.payu.com",
]


def get_stage_names() -> List[str]:
    """Retorna los nombres de las etapas en orden."""
    return [s["name"] for s in FLOW_STAGES]


def get_stage_by_name(name: str) -> Dict:
    """Busca una etapa por su nombre identificador."""
    for stage in FLOW_STAGES:
        if stage["name"] == name:
            return stage
    return {}
