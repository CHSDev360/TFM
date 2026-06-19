import streamlit as st
import requests
import json
import re
import io
import sqlite3
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
from openai import OpenAI
import ollama

# Selenium
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib.enums import TA_CENTER

from pathlib import Path

# queries
from sql_queries import (
    CREATE_FEEDBACK_TABLE,
    INSERT_FEEDBACK,
    SELECT_FEEDBACK,
    DELETE_FEEDBACK
)

# ─────────────────────────────────────────────
# BASE DE DATOS — FEEDBACK
# ─────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "feedback.db"

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute(CREATE_FEEDBACK_TABLE)
        con.commit()

def guardar_feedback(nombre, valoracion, comentario):
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            INSERT_FEEDBACK,
            (nombre.strip() or "Anónimo", valoracion, comentario.strip(), fecha)
        )
        con.commit()

def cargar_feedback():
    with sqlite3.connect(DB_PATH) as con:
        df = pd.read_sql_query(
            SELECT_FEEDBACK,
            con
        )
    return df

def borrar_feedback(feedback_id):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(DELETE_FEEDBACK, (feedback_id,))
        con.commit()

init_db()

# ─────────────────────────────────────────────
# CONFIG PÁGINA
# ─────────────────────────────────────────────
st.set_page_config(page_title="AI Web Vulnerability Scanner", layout="wide")
st.title("🔐 AI Web Vulnerability Scanner")
st.write("Analiza webs con IA para detectar vulnerabilidades")

# ─────────────────────────────────────────────
# DATOS GLOBALES — PROVEEDORES Y NIVELES
# ─────────────────────────────────────────────
PROVEEDORES = {
    "OpenAI": {
        "icon": "✦",
        "modelos": {
            "gpt-4o-mini": {"label": "⚡ GPT-4o mini", "desc": "Rápido y económico. Ideal para webs sencillas."},
            "gpt-4o":      {"label": "🧠 GPT-4o",      "desc": "Equilibrio velocidad/precisión. Recomendado para la mayoría de casos."},
            "o4-mini":     {"label": "🔍 o4-mini",      "desc": "Razonamiento compacto. Detecta vulnerabilidades complejas."},
            "o3":          {"label": "🚀 o3",            "desc": "Máxima capacidad de razonamiento. Análisis profundos y exhaustivos."},
        }
    },
    "DeepSeek": {
        "icon": "🐋",
        "modelos": {
            "deepseek-chat":     {"label": "💬 DeepSeek Chat",     "desc": "Modelo conversacional general. Rápido y eficiente."},
            "deepseek-reasoner": {"label": "🧠 DeepSeek Reasoner", "desc": "Modelo de razonamiento avanzado. Mayor profundidad de análisis."},
        }
    },
    "Ollama": {
        "icon": "🦙",
        "modelos": {
            "llama3":         {"label": "🦙 Llama 3",        "desc": "Modelo general de Meta. Buen equilibrio rendimiento/calidad."},
            "qwen3.5:4b":     {"label": "🌐 Qwen 3.5 4B",    "desc": "Modelo compacto de Alibaba. Eficiente en recursos."},
            "mistral":        {"label": "💨 Mistral",         "desc": "Modelo europeo, rápido y ligero. Buena respuesta general."},
            "gemma3:4b":      {"label": "💎 Gemma 3 4B",      "desc": "Modelo de Google, optimizado para razonamiento."},
            "phi4-mini":      {"label": "🔬 Phi-4 Mini",      "desc": "Modelo pequeño de Microsoft con alta capacidad analítica."},
            "deepseek-r1:7b": {"label": "🧩 DeepSeek R1 7B", "desc": "Versión local del modelo de razonamiento de DeepSeek."},
        }
    },
}

NIVELES_ESFUERZO = {
    "low":    {"label": "Low",    "max_tokens": 512,  "icon": "🟢", "desc": "Rápido y superficial. Detecta vulnerabilidades obvias. Bajo costo."},
    "medium": {"label": "Medium", "max_tokens": 1024, "icon": "🟡", "desc": "Equilibrio profundidad/velocidad. Recomendado para la mayoría."},
    "high":   {"label": "High",   "max_tokens": 2048, "icon": "🟠", "desc": "Análisis detallado. Explora más vectores de ataque."},
    "max":    {"label": "Max",    "max_tokens": 4096, "icon": "🔴", "desc": "Exhaustivo. Máxima profundidad. Mayor tiempo y costo."},
}

# ─────────────────────────────────────────────
# BARRA LATERAL — API KEYS
# ─────────────────────────────────────────────
with st.sidebar:
    st.header("🔑 Configuración de API Keys")
    st.caption("Las claves solo se usan durante la sesión y no se almacenan.")
    openai_api_key = st.text_input("OpenAI API Key", type="password", placeholder="sk-proj-...",
                                   help="Obtén tu clave en platform.openai.com")
    deepseek_api_key = st.text_input("DeepSeek API Key", type="password", placeholder="sk-...",
                                     help="Obtén tu clave en platform.deepseek.com")
    st.markdown("---")
    st.subheader("🦙 Ollama (local)")
    st.caption("Ollama no requiere API key — se ejecuta localmente en tu máquina.")
    st.markdown("---")
    st.caption("💡 Selecciona el proveedor, modelo e intensidad debajo.")

# ─────────────────────────────────────────────
# SESSION STATE — inicialización
# ─────────────────────────────────────────────
if "proveedor" not in st.session_state:
    st.session_state.proveedor = "OpenAI"
if "nivel_esfuerzo" not in st.session_state:
    st.session_state.nivel_esfuerzo = "medium"

# ─────────────────────────────────────────────
# SELECTOR DE MODO DE ENTRADA
# ─────────────────────────────────────────────
modo_entrada = st.radio(
    "📥 ¿Qué quieres analizar?",
    ["🌐 URL / Sitio web", "💻 Código backend"],
    horizontal=True,
    help="Elige si quieres analizar una web por su URL o pegar código fuente backend directamente."
)
st.markdown("")

# ── Modo URL ──────────────────────────────────
if modo_entrada == "🌐 URL / Sitio web":
    url            = st.text_input("🌐 Introduce una URL a analizar")
    codigo_backend = None
    lenguaje_codigo = None

    col_modo, col_glosario = st.columns(2)
    with col_modo:
        modo_extraccion = st.radio(
            "🔍 Modo de extracción",
            ["Básico (requests)", "Avanzado (Selenium)"],
            help="Básico: descarga el HTML estático. Avanzado: renderiza JavaScript y extrae formularios, scripts y endpoints."
        )
    with col_glosario:
        incluir_glosario = st.checkbox("📖 Incluir glosario de vulnerabilidades en el PDF", value=False)
    usar_selenium = modo_extraccion == "Avanzado (Selenium)"

# ── Modo Código Backend ───────────────────────
else:
    url           = None
    usar_selenium = False

    col_lang, col_glosario2 = st.columns([1, 2])
    with col_lang:
        lenguaje_codigo = st.selectbox(
            "🔤 Lenguaje",
            ["Python", "PHP", "JavaScript / Node.js", "Java", "C#", "Ruby", "Go", "Otro"],
            help="Selecciona el lenguaje del código que vas a pegar."
        )
    with col_glosario2:
        incluir_glosario = st.checkbox("📖 Incluir glosario de vulnerabilidades en el PDF", value=False)

    codigo_backend = st.text_area(
        "💻 Pega aquí tu código backend",
        height=300,
        placeholder="# Pega aquí tu código Python, PHP, Node.js, etc.\n# La IA buscará vulnerabilidades como SQL Injection, Command Injection, etc.",
        help="El código se enviará al modelo de IA seleccionado para detectar vulnerabilidades."
    )
    if codigo_backend and codigo_backend.strip():
        st.caption(f"📏 {len(codigo_backend)} caracteres · {len(codigo_backend.splitlines())} líneas")

st.markdown("---")

# ─────────────────────────────────────────────
# SELECTOR DE PROVEEDOR — píldoras
# ─────────────────────────────────────────────
st.markdown("**🤖 Proveedor de IA**")
cols_prov = st.columns(len(PROVEEDORES))
for col_p, (prov_key, prov_meta) in zip(cols_prov, PROVEEDORES.items()):
    with col_p:
        is_active = st.session_state.proveedor == prov_key
        btn_label = f"{prov_meta['icon']} **{prov_key}**" if is_active else f"{prov_meta['icon']} {prov_key}"
        if st.button(btn_label, key=f"prov_{prov_key}", use_container_width=True):
            st.session_state.proveedor = prov_key
            st.session_state.modelo_seleccionado = list(PROVEEDORES[prov_key]["modelos"].keys())[0]
            st.rerun()

proveedor_activo = st.session_state.proveedor
modelos_activos  = PROVEEDORES[proveedor_activo]["modelos"]

if "modelo_seleccionado" not in st.session_state or \
   st.session_state.modelo_seleccionado not in modelos_activos:
    st.session_state.modelo_seleccionado = list(modelos_activos.keys())[0]

# ─────────────────────────────────────────────
# SELECTOR DE MODELO + INTENSIDAD
# ─────────────────────────────────────────────
col_model, col_effort = st.columns([1, 1])

with col_model:
    st.markdown("**📦 Modelo**")
    modelo_seleccionado = st.selectbox(
        "Modelo",
        options=list(modelos_activos.keys()),
        format_func=lambda k: modelos_activos[k]["label"],
        index=list(modelos_activos.keys()).index(st.session_state.modelo_seleccionado),
        key="modelo_seleccionado",
        label_visibility="collapsed",
    )
    info_modelo = modelos_activos[modelo_seleccionado]
    st.caption(f"ℹ️ {info_modelo['desc']}")

with col_effort:
    st.markdown("**⚙️ Intensidad de análisis**")
    cols_pills = st.columns(4)
    for col_pill, (key, meta) in zip(cols_pills, NIVELES_ESFUERZO.items()):
        with col_pill:
            is_active  = st.session_state.nivel_esfuerzo == key
            pill_label = f"**{meta['label']}**" if is_active else meta["label"]
            if st.button(pill_label, key=f"effort_{key}", help=meta["desc"], use_container_width=True):
                st.session_state.nivel_esfuerzo = key
                st.rerun()

    nivel_esfuerzo          = st.session_state.nivel_esfuerzo
    info_esfuerzo           = NIVELES_ESFUERZO[nivel_esfuerzo]
    max_tokens_seleccionado = info_esfuerzo["max_tokens"]
    st.caption(f"{info_esfuerzo['icon']} **{info_esfuerzo['label']}** — {info_esfuerzo['desc']} | `max_tokens: {max_tokens_seleccionado}`")

# Variables finales de configuración
nivel_esfuerzo          = st.session_state.nivel_esfuerzo
info_esfuerzo           = NIVELES_ESFUERZO[nivel_esfuerzo]
max_tokens_seleccionado = info_esfuerzo["max_tokens"]

st.markdown("---")

# ─────────────────────────────────────────────
# GLOSARIO
# ─────────────────────────────────────────────
GLOSARIO = [
    (
        "SQL Injection (Inyección SQL)",
        "Es un ataque en el que un atacante introduce código SQL malicioso en un campo de texto "
        "(como un formulario de login o búsqueda) para manipular la base de datos de la aplicación. "
        "Puede permitir robar, modificar o eliminar datos, e incluso tomar el control del servidor.",
        "Un atacante escribe ' OR '1'='1 en el campo de contraseña para saltarse la autenticación."
    ),
    (
        "Cross-Site Scripting (XSS)",
        "Permite a un atacante inyectar código JavaScript malicioso en páginas web que otros usuarios "
        "visitan. El navegador de la víctima ejecuta ese código sin saber que es malicioso, lo que puede "
        "usarse para robar cookies de sesión, redirigir al usuario o mostrar contenido falso.",
        "Un atacante publica un comentario con <script>alert('hackeado')</script> y ese código se ejecuta "
        "en el navegador de cualquier persona que lea el comentario."
    ),
    (
        "CSRF (Cross-Site Request Forgery)",
        "Es un ataque que engaña al navegador de un usuario autenticado para que realice acciones no "
        "deseadas en una web donde ya tiene sesión iniciada. El usuario no se da cuenta de que está "
        "ejecutando una acción (como transferir dinero o cambiar su email) en su nombre.",
        "Un enlace malicioso en otro sitio web hace que el navegador de la víctima envíe una petición "
        "a su banco para transferir dinero, aprovechando que ya tiene sesión abierta."
    ),
    (
        "Command Injection (Inyección de Comandos)",
        "Ocurre cuando una aplicación web pasa datos introducidos por el usuario directamente al sistema "
        "operativo sin validarlos. Un atacante puede ejecutar comandos del sistema como si fuera el "
        "administrador del servidor, pudiendo leer archivos, instalar programas o apagar el servidor.",
        "En un campo que acepta una IP para hacer ping, el atacante escribe 127.0.0.1; rm -rf / "
        "para ejecutar comandos destructivos en el servidor."
    ),
    (
        "Directory Traversal (Traversal de Directorios)",
        "Permite a un atacante acceder a archivos y carpetas del servidor que no deberían ser accesibles "
        "desde la web. Usando secuencias especiales en la URL, puede navegar por el sistema de archivos "
        "del servidor y leer archivos sensibles como contraseñas o configuraciones.",
        "Un atacante modifica la URL a ../../etc/passwd para leer el archivo de contraseñas del servidor."
    ),
    (
        "Broken Access Control (Control de Acceso Roto)",
        "Ocurre cuando una aplicación no verifica correctamente si un usuario tiene permiso para realizar "
        "una acción o acceder a un recurso. Esto permite que usuarios normales accedan a funciones de "
        "administrador, vean datos de otros usuarios o realicen operaciones que deberían estar restringidas.",
        "Un usuario normal cambia el número de ID en la URL (ej: /usuario/123 por /usuario/124) "
        "y accede al perfil privado de otra persona sin ningún tipo de restricción."
    ),
]

LISTA_VULNERABILIDADES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "CSRF",
    "Command Injection",
    "Directory Traversal",
    "Broken Access Control",
]

# ─────────────────────────────────────────────
# EXTRACCIÓN HTML — BÁSICO (requests)
# ─────────────────────────────────────────────
def obtener_html_basico(url):
    r = requests.get(url, timeout=15)
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")
    st.info(f"📝 Formularios detectados: {len(forms)}")
    return {"html": r.text, "formularios": [], "scripts_externos": [],
            "scripts_inline": [], "endpoints": [], "archivos": []}


# ─────────────────────────────────────────────
# EXTRACCIÓN HTML — AVANZADO (Selenium)
# ─────────────────────────────────────────────
def _crear_driver_chrome():
    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-setuid-sandbox")
    options.add_argument("--remote-debugging-port=0")
    options.add_argument("--window-size=1920,1080")
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)


def _crear_driver_firefox():
    from webdriver_manager.firefox import GeckoDriverManager
    options = FirefoxOptions()
    options.add_argument("--headless")
    return webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)


def _extraer_recursos(driver, url):
    recursos = {
        "html": driver.page_source,
        "scripts_inline": [], "scripts_externos": [],
        "formularios": [], "endpoints": set(), "archivos": []
    }
    try:
        for script in driver.find_elements(By.TAG_NAME, "script"):
            c = script.get_attribute("innerHTML")
            if c and c.strip():
                recursos["scripts_inline"].append(c[:1000])
    except Exception as e:
        st.warning(f"Scripts inline: {e}")

    try:
        for script in driver.find_elements(By.CSS_SELECTOR, "script[src]"):
            src = script.get_attribute("src")
            if src:
                recursos["scripts_externos"].append(src)
    except Exception as e:
        st.warning(f"Scripts externos: {e}")

    try:
        for form in driver.find_elements(By.TAG_NAME, "form"):
            form_data = {
                "action": form.get_attribute("action") or "N/A",
                "method": form.get_attribute("method") or "GET",
                "inputs": []
            }
            for inp in form.find_elements(By.TAG_NAME, "input"):
                form_data["inputs"].append({
                    "name": inp.get_attribute("name"),
                    "type": inp.get_attribute("type"),
                    "id":   inp.get_attribute("id")
                })
            recursos["formularios"].append(form_data)
    except Exception as e:
        st.warning(f"Formularios: {e}")

    try:
        for link in driver.find_elements(By.TAG_NAME, "a"):
            href = link.get_attribute("href")
            if href and href.startswith("http"):
                recursos["endpoints"].add(href)
    except Exception as e:
        st.warning(f"Endpoints: {e}")

    for sc in recursos["scripts_inline"]:
        try:
            recursos["endpoints"].update(re.findall(r'["\']([/\w\-\.]+/api/[/\w\-\.]*)["\']', sc))
            recursos["endpoints"].update(re.findall(r'fetch\(["\']([^"\']+)["\']', sc))
            recursos["endpoints"].update(
                [u for _, u in re.findall(r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']', sc)])
        except Exception:
            continue

    try:
        selector = "a[href$='.pdf'], a[href$='.zip'], a[href$='.doc'], a[href$='.xls'], a[href$='.docx'], a[href$='.xlsx']"
        for archivo in driver.find_elements(By.CSS_SELECTOR, selector):
            href = archivo.get_attribute("href")
            if href:
                recursos["archivos"].append(href)
    except Exception as e:
        st.warning(f"Archivos: {e}")

    recursos["endpoints"] = list(recursos["endpoints"])[:50]
    return recursos


def obtener_html_selenium(url):
    driver = None
    navegador_usado = None
    try:
        driver = _crear_driver_chrome()
        navegador_usado = "Chrome"
    except Exception as e_chrome:
        st.warning(f"⚠️ Chrome no disponible ({type(e_chrome).__name__}). Probando Firefox...")
        try:
            driver = _crear_driver_firefox()
            navegador_usado = "Firefox"
        except Exception:
            st.error(
                "❌ **No se pudo iniciar ningún navegador para el modo Selenium.**\n\n"
                "Instala Chrome: `sudo apt install ./google-chrome-stable_current_amd64.deb`\n"
                "O Firefox: `sudo apt install firefox`\n\n"
                "Mientras tanto usa el **modo Básico (requests)**."
            )
            return None

    st.info(f"🌐 Navegador: {navegador_usado}")
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        return _extraer_recursos(driver, url)
    except Exception as e:
        st.error(f"❌ Error durante la extracción con Selenium: {e}")
        return None
    finally:
        driver.quit()

# ─────────────────────────────────────────────
# MOSTRAR MÉTRICAS SELENIUM EN UI
# ─────────────────────────────────────────────
def mostrar_metricas_selenium(recursos):
    formularios = recursos.get("formularios", [])
    scripts_ext = recursos.get("scripts_externos", [])
    scripts_inl = recursos.get("scripts_inline", [])
    endpoints   = recursos.get("endpoints", [])
    archivos    = recursos.get("archivos", [])

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("📝 Formularios", len(formularios))
    with m2: st.metric("📦 Scripts", len(scripts_ext) + len(scripts_inl))
    with m3: st.metric("🔗 Endpoints", len(endpoints))
    with m4: st.metric("📄 Archivos", len(archivos))

    with st.expander("📋 Ver Formularios Detectados"):
        st.json(formularios)
    with st.expander("🔍 Ver Endpoints Mapeados"):
        st.json(endpoints[:30])
    with st.expander("📜 Ver Scripts Externos"):
        st.json(scripts_ext[:20])
    with st.expander("📎 Ver Archivos Descargables"):
        if archivos:
            for a in archivos:
                nombre = a.split("/")[-1].split("?")[0]
                st.write(f"📄 **{nombre}**")
                st.caption(a)
        else:
            st.info("No se encontraron archivos descargables")


# ─────────────────────────────────────────────
# CONSTRUIR CONTENIDO PARA EL PROMPT
# ─────────────────────────────────────────────
def construir_contenido(url, recursos):
    if not recursos.get("formularios") and not recursos.get("endpoints"):
        return recursos["html"][:3000]
    return f"""
URL: {url}

HTML (primeros 2000 caracteres):
{recursos['html'][:2000]}

FORMULARIOS DETECTADOS ({len(recursos['formularios'])}):
{json.dumps(recursos['formularios'], indent=2, ensure_ascii=False)[:1500]}

SCRIPTS EXTERNOS ({len(recursos['scripts_externos'])}):
{json.dumps(recursos['scripts_externos'][:10], indent=2, ensure_ascii=False)}

SCRIPTS INLINE: {len(recursos['scripts_inline'])} detectados
Muestra:
{recursos['scripts_inline'][0][:800] if recursos['scripts_inline'] else 'N/A'}

ENDPOINTS MAPEADOS ({len(recursos['endpoints'])}):
{json.dumps(recursos['endpoints'][:20], indent=2, ensure_ascii=False)}

ARCHIVOS DESCARGABLES ({len(recursos['archivos'])}):
{json.dumps(recursos['archivos'][:10], indent=2, ensure_ascii=False)}
"""


# ─────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────
def crear_prompt_json(contenido):
    """Prompt JSON para análisis de URL/HTML."""
    return f"""
Analista de seguridad web: detecta vulnerabilidades en el contenido HTML/JS proporcionado.

VULNERABILIDADES A BUSCAR:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. CSRF (Cross-Site Request Forgery)
4. Command Injection
5. Directory Traversal
6. Broken Access Control

NIVELES:
- "confirmada": Evidencia directa en el código
- "sospecha": Indicios sin evidencia completa

FORMATO JSON obligatorio:
[
  {{
    "vulnerabilidad": "Nombre exacto",
    "nivel": "confirmada o sospecha",
    "ubicacion": "Elemento/línea",
    "descripcion": "Explicación breve",
    "evidencia": "Fragmento de código"
  }}
]

REGLAS:
- Si no hay vulnerabilidades: []
- Máximo 8 resultados
- Solo JSON válido, sin texto adicional

CONTENIDO:
{contenido}
"""


def crear_prompt_codigo_json(codigo, lenguaje):
    """Prompt JSON para análisis de código backend."""
    return f"""
Analista de seguridad: detecta vulnerabilidades en el siguiente código fuente {lenguaje}.

VULNERABILIDADES A BUSCAR:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. CSRF
4. Command Injection
5. Directory Traversal
6. Broken Access Control
7. Insecure Deserialization
8. Hardcoded Secrets
9. Manejo inseguro de errores
10. Otras vulnerabilidades

NIVELES:
- "confirmada": Evidencia directa en el código
- "sospecha": Indicios sin evidencia completa

FORMATO JSON obligatorio:
[
  {{
    "vulnerabilidad": "Nombre exacto",
    "nivel": "confirmada o sospecha",
    "linea": "Número o fragmento de código",
    "descripcion": "Explicación breve",
    "recomendacion": "Cómo corregirlo",
    "evidencia": "Fragmento de código vulnerable"
  }}
]

REGLAS:
- Si no hay vulnerabilidades: []
- Máximo 10 resultados
- Solo JSON válido, sin texto adicional

CÓDIGO ({lenguaje}):
```
{codigo[:4000]}
```
"""

# ─────────────────────────────────────────────
# FUNCIONES DE ANÁLISIS IA
# ─────────────────────────────────────────────
def analizar_api(cliente, modelo, contenido, max_tokens=1024, lenguaje_codigo=None):
    prompt = crear_prompt_codigo_json(contenido, lenguaje_codigo) if lenguaje_codigo else crear_prompt_json(contenido)
    response = cliente.chat.completions.create(
        model=modelo,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": "Experto en seguridad web y revisión de código seguro. Responde SIEMPRE con JSON válido, sin texto adicional."},
            {"role": "user",   "content": prompt}
        ]
    )
    return response.choices[0].message.content


def analizar_ollama(contenido, modelo="llama3", lenguaje_codigo=None):
    prompt = crear_prompt_codigo_json(contenido, lenguaje_codigo) if lenguaje_codigo else crear_prompt_json(contenido)

    # Primer intento
    response = ollama.chat(model=modelo, messages=[{"role": "user", "content": prompt}])
    resultado = response["message"]["content"]

    # Verificar si ya es JSON válido
    try:
        inicio = resultado.find("[")
        fin    = resultado.rfind("]") + 1
        if inicio != -1 and fin > inicio:
            json.loads(resultado[inicio:fin])
            return resultado
    except Exception:
        pass

    # Segundo intento — forzar JSON
    st.info("🔄 Reintentando con instrucción reforzada para obtener JSON...")
    response2 = ollama.chat(
        model=modelo,
        messages=[
            {"role": "user",      "content": prompt},
            {"role": "assistant", "content": resultado},
            {"role": "user",      "content": (
                "Tu respuesta anterior no estaba en formato JSON válido. "
                "Responde ÚNICAMENTE con el array JSON, sin texto adicional, "
                "sin explicaciones, sin markdown. Solo el array [ { ... } ]."
            )}
        ]
    )
    return response2["message"]["content"]


# ─────────────────────────────────────────────
# PARSEAR JSON — robusto con fallback a texto libre
# ─────────────────────────────────────────────
def parsear_resultado_json(resultado):
    # Intento 1: JSON puro entre [ ]
    try:
        inicio = resultado.find("[")
        fin    = resultado.rfind("]") + 1
        if inicio != -1 and fin > inicio:
            data = json.loads(resultado[inicio:fin])
            if isinstance(data, list) and len(data) > 0:
                return pd.DataFrame(data)
    except Exception:
        pass

    # Intento 2: bloques ```json ... ```
    try:
        match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', resultado, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
            return pd.DataFrame(data)
    except Exception:
        pass

    # Intento 3: parseo heurístico de texto libre
    MAPA_VULN = {
        "xss": "XSS (Cross-Site Scripting)",
        "cross-site scripting": "XSS (Cross-Site Scripting)",
        "sql injection": "SQL Injection",
        "csrf": "CSRF",
        "command injection": "Command Injection",
        "directory traversal": "Directory Traversal",
        "broken access control": "Broken Access Control",
    }
    filas = []
    bloques = re.split(r'\n\s*\d+\.\s+\*\*', resultado)
    if len(bloques) < 2:
        bloques = re.split(r'\n\s*\d+\.\s+', resultado)

    for bloque in bloques[1:]:
        vuln_nombre = "Desconocida"
        nivel       = "sospecha"
        ubicacion   = "N/A"
        descripcion = ""
        evidencia   = ""

        primera_linea = bloque.split("\n")[0].strip().strip("*").strip()
        for key, val in MAPA_VULN.items():
            if key in primera_linea.lower():
                vuln_nombre = val
                break
        else:
            vuln_nombre = primera_linea[:60] if primera_linea else "Desconocida"

        if "confirmada" in bloque.lower():
            nivel = "confirmada"

        m = re.search(r'[Uu]bicaci[oó]n[:\s]+(.+)', bloque)
        if m:
            ubicacion = m.group(1).strip().split("\n")[0]

        m = re.search(r'[Dd]escripci[oó]n[:\s]+(.+?)(?=\n[A-Z]|\nEvidencia|$)', bloque, re.DOTALL)
        if m:
            descripcion = m.group(1).strip()[:300]
        else:
            lineas = [l.strip() for l in bloque.split("\n") if l.strip() and not l.strip().startswith("**")]
            descripcion = " ".join(lineas[1:3])[:300]

        m = re.search(r'[Ee]videncia[:\s]+`?(.+?)`?(?:\n|$)', bloque)
        if m:
            evidencia = m.group(1).strip()[:200]
        else:
            fragmentos = re.findall(r'`([^`]+)`', bloque)
            evidencia  = fragmentos[0][:200] if fragmentos else ""

        if vuln_nombre != "Desconocida" or descripcion:
            filas.append({
                "vulnerabilidad": vuln_nombre,
                "nivel":          nivel,
                "ubicacion":      ubicacion,
                "descripcion":    descripcion,
                "evidencia":      evidencia,
            })

    if filas:
        st.info("ℹ️ El modelo respondió en texto libre — se procesó automáticamente.")
        return pd.DataFrame(filas)

    st.warning("⚠️ No se pudo parsear la respuesta. Mostrando resultado en bruto:")
    st.markdown(resultado)
    return pd.DataFrame()

# ─────────────────────────────────────────────
# GRID VISUAL DE SEMÁFORO
# ─────────────────────────────────────────────
def mostrar_grid_vulnerabilidades(df):
    confirmadas, sospechas = set(), set()
    if not df.empty and "vulnerabilidad" in df.columns:
        for _, row in df.iterrows():
            v     = str(row["vulnerabilidad"])
            nivel = str(row.get("nivel", "")).lower()
            for vuln in LISTA_VULNERABILIDADES:
                if vuln.lower() in v.lower():
                    if nivel == "confirmada":
                        confirmadas.add(vuln)
                    else:
                        sospechas.add(vuln)

    st.subheader("🛡️ Resumen de Vulnerabilidades")
    cols = st.columns(len(LISTA_VULNERABILIDADES))
    for col, vuln in zip(cols, LISTA_VULNERABILIDADES):
        with col:
            if vuln in confirmadas:
                icon, color, estado = "❌", "#f8d7da", "Detectada"
            elif vuln in sospechas:
                icon, color, estado = "⚠️", "#fff3cd", "Sospecha"
            else:
                icon, color, estado = "✅", "#d4edda", "Seguro"
            st.markdown(
                f"""<div style="background:{color};border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:1.8rem;">{icon}</div>
                    <div style="color:black;font-size:0.75rem;font-weight:600;margin-top:6px;">{vuln}</div>
                    <div style="font-size:0.7rem;color:#666;margin-top:4px;">{estado}</div>
                </div>""",
                unsafe_allow_html=True,
            )
    st.markdown("---")


# ─────────────────────────────────────────────
# GENERAR PDF
# ─────────────────────────────────────────────
def generar_pdf(url_analizada, modelo_usado, resultado_texto, con_glosario=False, df_json=None):
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm,   bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    estilo_titulo           = ParagraphStyle("Titulo",           parent=styles["Title"],   fontSize=20, textColor=colors.HexColor("#1a1a2e"), spaceAfter=6,  alignment=TA_CENTER)
    estilo_subtitulo        = ParagraphStyle("Subtitulo",        parent=styles["Normal"],  fontSize=11, textColor=colors.HexColor("#555555"), spaceAfter=4,  alignment=TA_CENTER)
    estilo_seccion          = ParagraphStyle("Seccion",          parent=styles["Heading2"],fontSize=13, textColor=colors.HexColor("#16213e"), spaceBefore=14, spaceAfter=6)
    estilo_cuerpo           = ParagraphStyle("Cuerpo",           parent=styles["Normal"],  fontSize=10, leading=16, textColor=colors.HexColor("#222222"), spaceAfter=4)
    estilo_meta             = ParagraphStyle("Meta",             parent=styles["Normal"],  fontSize=9,  textColor=colors.HexColor("#777777"), spaceAfter=2)
    estilo_glosario_titulo  = ParagraphStyle("GlosarioTitulo",   parent=styles["Heading3"],fontSize=11, textColor=colors.HexColor("#16213e"), spaceBefore=10, spaceAfter=3)
    estilo_glosario_def     = ParagraphStyle("GlosarioDef",      parent=styles["Normal"],  fontSize=9,  leading=14, textColor=colors.HexColor("#333333"), spaceAfter=2, leftIndent=12)
    estilo_glosario_ejemplo = ParagraphStyle("GlosarioEjemplo",  parent=styles["Normal"],  fontSize=9,  leading=13, textColor=colors.HexColor("#555555"), spaceAfter=6, leftIndent=12, fontName="Helvetica-Oblique")

    elementos = []
    elementos.append(Paragraph("🔐 AI Web Vulnerability Scanner", estilo_titulo))
    elementos.append(Paragraph("Informe de Análisis de Seguridad Web", estilo_subtitulo))
    elementos.append(Spacer(1, 0.3*cm))
    elementos.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    elementos.append(Spacer(1, 0.4*cm))

    fecha      = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    tabla_meta = Table([
        ["URL / Fuente analizada:", url_analizada],
        ["Modelo IA utilizado:",    modelo_usado],
        ["Fecha del análisis:",     fecha],
    ], colWidths=[4.5*cm, 13*cm])
    tabla_meta.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 0), (0, -1),  colors.HexColor("#333333")),
        ("TEXTCOLOR",     (1, 0), (1, -1),  colors.HexColor("#555555")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
    ]))
    elementos.append(tabla_meta)
    elementos.append(Spacer(1, 0.4*cm))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    elementos.append(Paragraph("Resultados del Análisis", estilo_seccion))

    if df_json is not None and not df_json.empty:
        columnas    = [c for c in ["vulnerabilidad", "nivel", "ubicacion", "linea", "descripcion", "recomendacion", "evidencia"] if c in df_json.columns]
        encabezados = [c.capitalize() for c in columnas]
        ANCHO_UTIL  = 482
        anchos_col  = {
            "vulnerabilidad": 0.17, "nivel": 0.09, "ubicacion": 0.13, "linea": 0.10,
            "descripcion": 0.25, "recomendacion": 0.15, "evidencia": 0.20
        }
        col_widths = [ANCHO_UTIL * anchos_col.get(c, 0.15) for c in columnas]

        estilo_celda    = ParagraphStyle("CeldaTabla",   parent=styles["Normal"], fontSize=7, leading=10, wordWrap="CJK")
        estilo_cabecera = ParagraphStyle("CabeceraTabla",parent=styles["Normal"], fontSize=7, leading=10, textColor=colors.white, fontName="Helvetica-Bold")

        filas = [[Paragraph(h, estilo_cabecera) for h in encabezados]]
        for _, row in df_json.iterrows():
            filas.append([Paragraph(str(row[c])[:300], estilo_celda) for c in columnas])

        tabla_vuln = Table(filas, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        tabla_vuln.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1a1a2e")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ]))
        elementos.append(tabla_vuln)
    else:
        for linea in resultado_texto.split("\n"):
            linea = linea.strip()
            if not linea:
                elementos.append(Spacer(1, 0.2*cm))
                continue
            linea = linea.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if linea.startswith(("**", "a.", "b.", "c.", "d.", "1.", "2.", "3.", "4.", "5.", "6.")):
                linea = f"<b>{linea}</b>"
            elementos.append(Paragraph(linea, estilo_cuerpo))

    if con_glosario:
        elementos.append(Spacer(1, 0.6*cm))
        elementos.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a1a2e")))
        elementos.append(Paragraph("Glosario de Vulnerabilidades", estilo_seccion))
        elementos.append(Paragraph(
            "Esta sección explica de forma sencilla cada tipo de vulnerabilidad para personas "
            "sin conocimientos previos en ciberseguridad.", estilo_cuerpo))
        elementos.append(Spacer(1, 0.3*cm))
        for nombre, definicion, ejemplo in GLOSARIO:
            elementos.append(Paragraph(nombre, estilo_glosario_titulo))
            elementos.append(Paragraph(definicion, estilo_glosario_def))
            elementos.append(Paragraph(f"Ejemplo: {ejemplo}", estilo_glosario_ejemplo))
            elementos.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#dddddd")))

    elementos.append(Spacer(1, 0.6*cm))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    elementos.append(Spacer(1, 0.2*cm))
    elementos.append(Paragraph(
        "Informe generado automáticamente por AI Web Vulnerability Scanner · Solo para uso educativo y de investigación.",
        estilo_meta))

    doc.build(elementos)
    buffer.seek(0)
    return buffer

# ─────────────────────────────────────────────
# MOSTRAR RESULTADO JSON + GRID + BOTONES
# ─────────────────────────────────────────────
def mostrar_resultado_json(titulo, modelo_usado, fuente, resultado_raw):
    st.subheader(titulo)
    df = parsear_resultado_json(resultado_raw)
    mostrar_grid_vulnerabilidades(df)

    if df.empty:
        st.success("✅ No se detectaron vulnerabilidades")
    else:
        st.subheader("📊 Detalle de Vulnerabilidades")
        st.dataframe(df, use_container_width=True)
        st.download_button("⬇️ Descargar CSV", df.to_csv(index=False),
                           "vulnerabilidades.csv", "text/csv")

    pdf    = generar_pdf(fuente, modelo_usado, resultado_raw, con_glosario=incluir_glosario, df_json=df)
    nombre = f"informe_{modelo_usado.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    st.download_button("📄 Descargar informe PDF", data=pdf, file_name=nombre, mime="application/pdf")


# ─────────────────────────────────────────────
# BOTÓN ÚNICO DE ANÁLISIS
# ─────────────────────────────────────────────
prov_icon    = PROVEEDORES[proveedor_activo]["icon"]
btn_analizar = f"🔍 Analizar con {prov_icon} {proveedor_activo} — {info_modelo['label']}"

if st.button(btn_analizar, type="primary", use_container_width=True):

    # ── Validaciones ──────────────────────────
    if modo_entrada == "🌐 URL / Sitio web" and (not url or not url.strip()):
        st.warning("❗ Por favor, introduce una URL válida.")
        st.stop()

    if modo_entrada == "💻 Código backend" and (not codigo_backend or not codigo_backend.strip()):
        st.warning("❗ Por favor, pega el código que quieres analizar.")
        st.stop()

    if proveedor_activo == "OpenAI" and not openai_api_key.strip():
        st.warning("🔑 Introduce tu OpenAI API Key en la barra lateral.")
        st.stop()

    if proveedor_activo == "DeepSeek" and not deepseek_api_key.strip():
        st.warning("🔑 Introduce tu DeepSeek API Key en la barra lateral.")
        st.stop()

    # ── Preparar contenido ────────────────────
    if modo_entrada == "🌐 URL / Sitio web":
        with st.spinner("🌐 Extrayendo contenido de la web..."):
            recursos = obtener_html_selenium(url) if usar_selenium else obtener_html_basico(url)
        if not recursos:
            st.stop()
        if usar_selenium:
            mostrar_metricas_selenium(recursos)
        contenido = construir_contenido(url, recursos)
        fuente    = url
        lang      = None
    else:
        contenido = codigo_backend
        fuente    = f"[Código {lenguaje_codigo}]"
        lang      = lenguaje_codigo

    # ── Análisis según proveedor ──────────────
    nombre_modelo_label = f"{proveedor_activo} {info_modelo['label']} · {info_esfuerzo['label']}"

    if proveedor_activo == "OpenAI":
        with st.spinner(f"🤖 Analizando con {info_modelo['label']} · intensidad {info_esfuerzo['label']}..."):
            cliente   = OpenAI(api_key=openai_api_key.strip())
            resultado = analizar_api(cliente, modelo_seleccionado, contenido,
                                     max_tokens=max_tokens_seleccionado, lenguaje_codigo=lang)

    elif proveedor_activo == "DeepSeek":
        with st.spinner(f"🐋 Analizando con {info_modelo['label']} · intensidad {info_esfuerzo['label']}..."):
            cliente   = OpenAI(api_key=deepseek_api_key.strip(), base_url="https://api.deepseek.com")
            resultado = analizar_api(cliente, modelo_seleccionado, contenido,
                                     max_tokens=max_tokens_seleccionado, lenguaje_codigo=lang)

    elif proveedor_activo == "Ollama":
        with st.spinner(f"🦙 Analizando localmente con {info_modelo['label']}..."):
            resultado = analizar_ollama(contenido, modelo=modelo_seleccionado, lenguaje_codigo=lang)

    mostrar_resultado_json(
        f"Resultado — {info_modelo['label']} ({info_esfuerzo['label']})",
        nombre_modelo_label,
        fuente,
        resultado
    )

# ─────────────────────────────────────────────
# SECCIÓN FEEDBACK
# ─────────────────────────────────────────────
st.markdown("---")
st.header("💬 Feedback y Comentarios")
st.write("¿Qué te ha parecido la herramienta? Deja tu opinión para ayudarnos a mejorar.")

tab_nuevo, tab_ver = st.tabs(["✍️ Dejar comentario", "📋 Ver comentarios"])

# ── Tab: formulario nuevo ──────────────────────
with tab_nuevo:
    with st.form("form_feedback", clear_on_submit=True):
        col_nombre, col_val = st.columns([2, 1])
        with col_nombre:
            fb_nombre = st.text_input("Tu nombre (opcional)", placeholder="Anónimo", max_chars=60)
        with col_val:
            fb_valoracion = st.select_slider(
                "Valoración",
                options=[1, 2, 3, 4, 5],
                value=5,
                format_func=lambda x: "⭐" * x
            )
        fb_comentario = st.text_area(
            "Comentario *",
            placeholder="Cuéntanos tu experiencia, sugerencias o cualquier problema que hayas encontrado...",
            height=120,
            max_chars=1000
        )
        enviado = st.form_submit_button("📨 Enviar feedback", use_container_width=True)
        if enviado:
            if not fb_comentario.strip():
                st.warning("❗ El comentario no puede estar vacío.")
            else:
                guardar_feedback(fb_nombre, fb_valoracion, fb_comentario)
                st.success("✅ ¡Gracias por tu feedback! Ha sido guardado correctamente.")

# ── Tab: ver comentarios ───────────────────────
with tab_ver:
    df_fb = cargar_feedback()

    if df_fb.empty:
        st.info("Todavía no hay comentarios. ¡Sé el primero en dejar uno!")
    else:
        media = df_fb["valoracion"].mean()
        total = len(df_fb)

        mc1, mc2, mc3 = st.columns(3)
        with mc1: st.metric("💬 Total comentarios", total)
        with mc2: st.metric("⭐ Valoración media", f"{media:.1f} / 5")
        with mc3:
            mejor = df_fb["valoracion"].value_counts().idxmax()
            st.metric("🏆 Puntuación más frecuente", "⭐" * mejor)

        st.markdown("")

        for _, row in df_fb.iterrows():
            estrellas   = "⭐" * int(row["valoracion"])
            nombre      = row["nombre"] or "Anónimo"
            color_fondo = {5: "#d4edda", 4: "#d1ecf1", 3: "#fff3cd", 2: "#fde8d8", 1: "#f8d7da"}.get(
                int(row["valoracion"]), "#f5f5f5"
            )
            st.markdown(
                f"""<div style="background:{color_fondo};border-radius:8px;padding:14px;margin-bottom:10px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-weight:600;color:#222;">{nombre}</span>
                        <span style="font-size:0.85rem;color:#666;">{row['fecha']}</span>
                    </div>
                    <div style="font-size:1.1rem;margin:4px 0;">{estrellas}</div>
                    <div style="color:#333;font-size:0.95rem;">{row['comentario']}</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown("")

        with st.expander("🗑️ Borrar un comentario (moderación)"):
            ids_disponibles = df_fb["id"].tolist()
            id_borrar = st.selectbox(
                "Selecciona el ID del comentario a borrar",
                ids_disponibles,
                format_func=lambda x: f"ID {x} — {df_fb[df_fb['id']==x]['nombre'].values[0]} ({df_fb[df_fb['id']==x]['fecha'].values[0]})"
            )
            if st.button("🗑️ Borrar comentario seleccionado", type="secondary"):
                borrar_feedback(id_borrar)
                st.success(f"Comentario ID {id_borrar} eliminado.")
                st.rerun()

        st.download_button(
            "⬇️ Exportar todos los comentarios (CSV)",
            data=df_fb.to_csv(index=False),
            file_name=f"feedback_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )
