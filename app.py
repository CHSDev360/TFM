
import streamlit as st
import requests
import json
import re
import io
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

# ─────────────────────────────────────────────
# CLIENTES IA
# ─────────────────────────────────────────────
openai_client = OpenAI(
    api_key="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"
)

deepseek_client = OpenAI(
    api_key="sk-5d51da9401fa4c3dbb1192ca12e45f41",
    base_url="https://api.deepseek.com"
)

# ─────────────────────────────────────────────
# CONFIG PÁGINA
# ─────────────────────────────────────────────
st.set_page_config(page_title="AI Web Vulnerability Scanner", layout="wide")
st.title("🔐 AI Web Vulnerability Scanner")
st.write("Analiza webs con IA para detectar vulnerabilidades")

# ─────────────────────────────────────────────
# INPUTS
# ─────────────────────────────────────────────
url = st.text_input("🌐 Introduce una URL a analizar")

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

st.markdown("---")
col1, col2, col3 = st.columns(3)

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
    """Intenta crear un driver de Chrome con las opciones adecuadas para cada entorno."""
    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")   # imprescindible en WSL/Docker
    options.add_argument("--disable-setuid-sandbox")
    options.add_argument("--remote-debugging-port=0")
    options.add_argument("--window-size=1920,1080")
    return webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )


def _crear_driver_firefox():
    """Fallback: Firefox con geckodriver si Chrome no está disponible."""
    from webdriver_manager.firefox import GeckoDriverManager

    options = FirefoxOptions()
    options.add_argument("--headless")
    return webdriver.Firefox(
        service=FirefoxService(GeckoDriverManager().install()),
        options=options
    )


def _extraer_recursos(driver, url):
    """Extrae formularios, scripts, endpoints y archivos del driver activo."""
    recursos = {
        "html": driver.page_source,
        "scripts_inline": [],
        "scripts_externos": [],
        "formularios": [],
        "endpoints": set(),
        "archivos": []
    }

    # Scripts inline
    try:
        for script in driver.find_elements(By.TAG_NAME, "script"):
            contenido = script.get_attribute("innerHTML")
            if contenido and contenido.strip():
                recursos["scripts_inline"].append(contenido[:1000])
    except Exception as e:
        st.warning(f"Scripts inline: {e}")

    # Scripts externos
    try:
        for script in driver.find_elements(By.CSS_SELECTOR, "script[src]"):
            src = script.get_attribute("src")
            if src:
                recursos["scripts_externos"].append(src)
    except Exception as e:
        st.warning(f"Scripts externos: {e}")

    # Formularios
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
                    "id": inp.get_attribute("id")
                })
            recursos["formularios"].append(form_data)
    except Exception as e:
        st.warning(f"Formularios: {e}")

    # Endpoints (links)
    try:
        for link in driver.find_elements(By.TAG_NAME, "a"):
            href = link.get_attribute("href")
            if href and href.startswith("http"):
                recursos["endpoints"].add(href)
    except Exception as e:
        st.warning(f"Endpoints: {e}")

    # Endpoints en JS (fetch, axios)
    for script_content in recursos["scripts_inline"]:
        try:
            recursos["endpoints"].update(
                re.findall(r'["\']([/\w\-\.]+/api/[/\w\-\.]*)["\']', script_content))
            recursos["endpoints"].update(
                re.findall(r'fetch\(["\']([^"\']+)["\']', script_content))
            recursos["endpoints"].update(
                [u for _, u in re.findall(r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']', script_content)])
        except Exception:
            continue

    # Archivos descargables
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
    """
    Intenta usar Chrome primero. Si falla, prueba Firefox.
    Si ambos fallan, muestra instrucciones claras y devuelve None.
    """
    driver = None
    navegador_usado = None

    # Intentar Chrome
    try:
        driver = _crear_driver_chrome()
        navegador_usado = "Chrome"
    except Exception as e_chrome:
        st.warning(f"⚠️ Chrome no disponible ({type(e_chrome).__name__}). Probando Firefox...")
        # Intentar Firefox como fallback
        try:
            driver = _crear_driver_firefox()
            navegador_usado = "Firefox"
        except Exception as e_firefox:
            st.error(
                "❌ **No se pudo iniciar ningún navegador para el modo Selenium.**\n\n"
                "**Solución en WSL/Linux:** instala Chrome con estos comandos en tu terminal:\n"
                "```\n"
                "wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb\n"
                "sudo apt install ./google-chrome-stable_current_amd64.deb\n"
                "```\n"
                "O instala Firefox:\n"
                "```\n"
                "sudo apt install firefox\n"
                "```\n\n"
                "Mientras tanto puedes usar el **modo Básico (requests)** que no requiere navegador."
            )
            return None

    st.info(f"🌐 Navegador: {navegador_usado}")

    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
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
        # Modo básico: solo HTML
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
def crear_prompt_texto(contenido):
    """Prompt para OpenAI y DeepSeek — respuesta en texto estructurado."""
    return f"""
Eres un experto en ciberseguridad y pentesting web.

Tu objetivo es analizar el contenido de un sitio web y detectar vulnerabilidades de forma ordenada y metódica.
Todas las respuestas deben seguir estrictamente este formato estándar:

**Vulnerabilidades a revisar, siempre en este orden:**
1. SQL Injection
2. Cross Site Scripting (XSS)
3. CSRF
4. Command Injection
5. Directory Traversal
6. Broken Access Control

**Formato para cada vulnerabilidad detectada:**
    a. Vulnerabilidad: <nombre exacto>
    b. Ubicación: <formulario, input, parámetro, URL, etc.>
    c. Descripción: <breve explicación>
    d. Ejemplo de ataque: <payload o comando, máximo 1 línea>

**Instrucciones:**
- Responde solo si detectas vulnerabilidades.
- Idioma: español.
- Si no hay vulnerabilidades: "No se detectaron vulnerabilidades."

**Contenido a analizar:**
{contenido}
"""


def crear_prompt_json(contenido):
    """Prompt para Ollama — respuesta en JSON estructurado."""
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

# ─────────────────────────────────────────────
# FUNCIONES DE ANÁLISIS IA
# ─────────────────────────────────────────────
def analizar_api(cliente, modelo, contenido):
    prompt = crear_prompt_texto(contenido)
    response = cliente.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": "Experto en seguridad web"},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content


def analizar_ollama(contenido):
    prompt = crear_prompt_json(contenido)
    response = ollama.chat(
        model="llama3",
        messages=[{"role": "user", "content": prompt}]
    )
    return response["message"]["content"]


# ─────────────────────────────────────────────
# PARSEAR JSON (respuesta Ollama)
# ─────────────────────────────────────────────
def parsear_resultado_json(resultado):
    try:
        inicio = resultado.find("[")
        fin = resultado.rfind("]") + 1
        data = json.loads(resultado[inicio:fin])
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"⚠️ Error parseando JSON: {e}")
        st.code(resultado)
        return pd.DataFrame()


# ─────────────────────────────────────────────
# GRID VISUAL DE SEMÁFORO
# ─────────────────────────────────────────────
def mostrar_grid_vulnerabilidades(df):
    confirmadas, sospechas = set(), set()

    if not df.empty and "vulnerabilidad" in df.columns:
        for _, row in df.iterrows():
            v = str(row["vulnerabilidad"])
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
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    estilo_titulo = ParagraphStyle("Titulo", parent=styles["Title"], fontSize=20,
                                   textColor=colors.HexColor("#1a1a2e"), spaceAfter=6, alignment=TA_CENTER)
    estilo_subtitulo = ParagraphStyle("Subtitulo", parent=styles["Normal"], fontSize=11,
                                      textColor=colors.HexColor("#555555"), spaceAfter=4, alignment=TA_CENTER)
    estilo_seccion = ParagraphStyle("Seccion", parent=styles["Heading2"], fontSize=13,
                                    textColor=colors.HexColor("#16213e"), spaceBefore=14, spaceAfter=6)
    estilo_cuerpo = ParagraphStyle("Cuerpo", parent=styles["Normal"], fontSize=10,
                                   leading=16, textColor=colors.HexColor("#222222"), spaceAfter=4)
    estilo_meta = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9,
                                 textColor=colors.HexColor("#777777"), spaceAfter=2)
    estilo_glosario_titulo = ParagraphStyle("GlosarioTitulo", parent=styles["Heading3"], fontSize=11,
                                            textColor=colors.HexColor("#16213e"), spaceBefore=10, spaceAfter=3)
    estilo_glosario_def = ParagraphStyle("GlosarioDef", parent=styles["Normal"], fontSize=9,
                                         leading=14, textColor=colors.HexColor("#333333"), spaceAfter=2, leftIndent=12)
    estilo_glosario_ejemplo = ParagraphStyle("GlosarioEjemplo", parent=styles["Normal"], fontSize=9,
                                             leading=13, textColor=colors.HexColor("#555555"), spaceAfter=6,
                                             leftIndent=12, fontName="Helvetica-Oblique")

    elementos = []

    # Cabecera
    elementos.append(Paragraph("🔐 AI Web Vulnerability Scanner", estilo_titulo))
    elementos.append(Paragraph("Informe de Análisis de Seguridad Web", estilo_subtitulo))
    elementos.append(Spacer(1, 0.3*cm))
    elementos.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    elementos.append(Spacer(1, 0.4*cm))

    # Metadatos
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    tabla_meta = Table([
        ["URL analizada:", url_analizada],
        ["Modelo IA utilizado:", modelo_usado],
        ["Fecha del análisis:", fecha],
    ], colWidths=[4.5*cm, 13*cm])
    tabla_meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#333333")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#555555")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elementos.append(tabla_meta)
    elementos.append(Spacer(1, 0.4*cm))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))

    # Resultados
    elementos.append(Paragraph("Resultados del Análisis", estilo_seccion))

    if df_json is not None and not df_json.empty:
        # Tabla estructurada para resultados JSON (Ollama)
        columnas = [c for c in ["vulnerabilidad", "nivel", "ubicacion", "descripcion", "evidencia"] if c in df_json.columns]
        encabezados = [c.capitalize() for c in columnas]
        datos_tabla = [encabezados] + [[str(row[c])[:120] for c in columnas] for _, row in df_json.iterrows()]
        tabla_vuln = Table(datos_tabla, repeatRows=1, hAlign="LEFT")
        tabla_vuln.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        elementos.append(tabla_vuln)
    else:
        # Texto formateado para OpenAI / DeepSeek
        for linea in resultado_texto.split("\n"):
            linea = linea.strip()
            if not linea:
                elementos.append(Spacer(1, 0.2*cm))
                continue
            linea = linea.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if linea.startswith(("**", "a.", "b.", "c.", "d.", "1.", "2.", "3.", "4.", "5.", "6.")):
                linea = f"<b>{linea}</b>"
            elementos.append(Paragraph(linea, estilo_cuerpo))

    # Glosario opcional
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

    # Pie
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
# MOSTRAR RESULTADO TEXTO + BOTÓN PDF
# ─────────────────────────────────────────────
def mostrar_resultado_texto(titulo, modelo_usado, url_analizada, resultado):
    st.subheader(titulo)
    st.write(resultado)
    pdf = generar_pdf(url_analizada, modelo_usado, resultado, con_glosario=incluir_glosario)
    nombre = f"informe_{modelo_usado.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    st.download_button("📄 Descargar informe PDF", data=pdf, file_name=nombre, mime="application/pdf")


# ─────────────────────────────────────────────
# MOSTRAR RESULTADO JSON + GRID + BOTONES
# ─────────────────────────────────────────────
def mostrar_resultado_json(titulo, modelo_usado, url_analizada, resultado_raw):
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

    pdf = generar_pdf(url_analizada, modelo_usado, resultado_raw,
                      con_glosario=incluir_glosario, df_json=df)
    nombre = f"informe_{modelo_usado.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    st.download_button("📄 Descargar informe PDF", data=pdf, file_name=nombre, mime="application/pdf")

# ─────────────────────────────────────────────
# BOTONES DE ANÁLISIS
# ─────────────────────────────────────────────
with col1:
    if st.button("Analizar con OpenAI"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            with st.spinner("Extrayendo contenido..."):
                recursos = obtener_html_selenium(url) if usar_selenium else obtener_html_basico(url)
            if recursos:
                if usar_selenium:
                    mostrar_metricas_selenium(recursos)
                contenido = construir_contenido(url, recursos)
                with st.spinner("Analizando con OpenAI..."):
                    resultado = analizar_api(openai_client, "gpt-4o-mini", contenido)
                mostrar_resultado_texto("Resultado OpenAI", "OpenAI GPT-4o-mini", url, resultado)

with col2:
    if st.button("Analizar con DeepSeek"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            with st.spinner("Extrayendo contenido..."):
                recursos = obtener_html_selenium(url) if usar_selenium else obtener_html_basico(url)
            if recursos:
                if usar_selenium:
                    mostrar_metricas_selenium(recursos)
                contenido = construir_contenido(url, recursos)
                with st.spinner("Analizando con DeepSeek..."):
                    resultado = analizar_api(deepseek_client, "deepseek-chat", contenido)
                mostrar_resultado_texto("Resultado DeepSeek", "DeepSeek Chat", url, resultado)

with col3:
    if st.button("Analizar con Ollama (local)"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            with st.spinner("Extrayendo contenido..."):
                recursos = obtener_html_selenium(url) if usar_selenium else obtener_html_basico(url)
            if recursos:
                if usar_selenium:
                    mostrar_metricas_selenium(recursos)
                contenido = construir_contenido(url, recursos)
                with st.spinner("Analizando con Ollama..."):
                    resultado = analizar_ollama(contenido)
                mostrar_resultado_json("Resultado Ollama", "Ollama LLaMA3", url, resultado)
