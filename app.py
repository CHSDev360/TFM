import streamlit as st
import requests
from bs4 import BeautifulSoup
from openai import OpenAI
import ollama
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# CLIENTES IA
openai_client = OpenAI(
    api_key="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"
)

deepseek_client = OpenAI(
    api_key="sk-5d51da9401fa4c3dbb1192ca12e45f41",
    base_url="https://api.deepseek.com"
)

st.set_page_config(page_title="AI Web Vulnerability Scanner")

st.title("🔐 AI Web Vulnerability Scanner")
st.write("Analiza webs con IA para detectar vulnerabilidades")

# INPUT URL
url = st.text_input("Introduce una URL a analizar")

col1, col2, col3 = st.columns(3)

incluir_glosario = st.checkbox("📖 Incluir glosario de vulnerabilidades en el PDF", value=False)


# ─────────────────────────────────────────────
# GLOSARIO DE VULNERABILIDADES
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


# ─────────────────────────────────────────────
# FUNCIÓN: GENERAR PDF
# ─────────────────────────────────────────────
def generar_pdf(url_analizada, modelo_usado, resultado_texto, con_glosario=False):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()

    # Estilos personalizados
    estilo_titulo = ParagraphStyle(
        "Titulo",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    estilo_subtitulo = ParagraphStyle(
        "Subtitulo",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#555555"),
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    estilo_seccion = ParagraphStyle(
        "Seccion",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#16213e"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=4,
    )
    estilo_cuerpo = ParagraphStyle(
        "Cuerpo",
        parent=styles["Normal"],
        fontSize=10,
        leading=16,
        textColor=colors.HexColor("#222222"),
        spaceAfter=4,
    )
    estilo_meta = ParagraphStyle(
        "Meta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#777777"),
        spaceAfter=2,
    )

    estilo_glosario_titulo = ParagraphStyle(
        "GlosarioTitulo",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#16213e"),
        spaceBefore=10,
        spaceAfter=3,
        leftIndent=0,
    )
    estilo_glosario_def = ParagraphStyle(
        "GlosarioDef",
        parent=styles["Normal"],
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#333333"),
        spaceAfter=2,
        leftIndent=12,
    )
    estilo_glosario_ejemplo = ParagraphStyle(
        "GlosarioEjemplo",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#555555"),
        spaceAfter=6,
        leftIndent=12,
        fontName="Helvetica-Oblique",
    )

    elementos = []

    # ── Cabecera ──
    elementos.append(Paragraph("🔐 AI Web Vulnerability Scanner", estilo_titulo))
    elementos.append(Paragraph("Informe de Análisis de Seguridad Web", estilo_subtitulo))
    elementos.append(Spacer(1, 0.3 * cm))
    elementos.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    elementos.append(Spacer(1, 0.4 * cm))

    # ── Metadatos ──
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    datos_meta = [
        ["URL analizada:", url_analizada],
        ["Modelo IA utilizado:", modelo_usado],
        ["Fecha del análisis:", fecha],
    ]
    tabla_meta = Table(datos_meta, colWidths=[4.5 * cm, 13 * cm])
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
    elementos.append(Spacer(1, 0.4 * cm))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))

    # ── Resultados ──
    elementos.append(Paragraph("Resultados del Análisis", estilo_seccion))

    # Procesar el texto línea a línea para mantener el formato
    for linea in resultado_texto.split("\n"):
        linea = linea.strip()
        if not linea:
            elementos.append(Spacer(1, 0.2 * cm))
            continue
        # Escapar caracteres especiales de XML/HTML para ReportLab
        linea = linea.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        # Negrita para líneas que empiezan con marcadores de vulnerabilidad
        if linea.startswith(("**", "a.", "b.", "c.", "d.", "1.", "2.", "3.", "4.", "5.", "6.")):
            linea = f"<b>{linea}</b>"
        elementos.append(Paragraph(linea, estilo_cuerpo))

    # ── Glosario (opcional) ──
    if con_glosario:
        elementos.append(Spacer(1, 0.6 * cm))
        elementos.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a1a2e")))
        elementos.append(Paragraph("Glosario de Vulnerabilidades", estilo_seccion))
        elementos.append(Paragraph(
            "Esta sección explica de forma sencilla cada tipo de vulnerabilidad para personas "
            "sin conocimientos previos en ciberseguridad.",
            estilo_cuerpo
        ))
        elementos.append(Spacer(1, 0.3 * cm))

        for nombre, definicion, ejemplo in GLOSARIO:
            elementos.append(Paragraph(nombre, estilo_glosario_titulo))
            elementos.append(Paragraph(definicion, estilo_glosario_def))
            elementos.append(Paragraph(f"Ejemplo: {ejemplo}", estilo_glosario_ejemplo))
            elementos.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#dddddd")))

    # ── Pie de página ──
    elementos.append(Spacer(1, 0.6 * cm))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    elementos.append(Spacer(1, 0.2 * cm))
    elementos.append(Paragraph(
        "Informe generado automáticamente por AI Web Vulnerability Scanner · Solo para uso educativo y de investigación.",
        estilo_meta
    ))

    doc.build(elementos)
    buffer.seek(0)
    return buffer


# ─────────────────────────────────────────────
# FUNCIÓN: MOSTRAR RESULTADO + BOTÓN PDF
# ─────────────────────────────────────────────
def mostrar_resultado_con_pdf(titulo, modelo_usado, url_analizada, resultado):
    st.subheader(titulo)
    st.write(resultado)

    pdf_buffer = generar_pdf(url_analizada, modelo_usado, resultado, con_glosario=incluir_glosario)
    nombre_archivo = f"informe_{modelo_usado.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    st.download_button(
        label="📄 Descargar informe PDF",
        data=pdf_buffer,
        file_name=nombre_archivo,
        mime="application/pdf"
    )


# ─────────────────────────────────────────────
# FUNCIÓN: CREAR PROMPT
# ─────────────────────────────────────────────
def crear_prompt(html):
    return f"""
Eres un experto en ciberseguridad y pentesting web.

Tu objetivo es **analizar el HTML de un sitio web y detectar vulnerabilidades** de forma **ordenada y metódica**.  
Todas las respuestas deben seguir estrictamente este **formato estándar** y mantenerse igual en futuras consultas:

**Vulnerabilidades a revisar, siempre en este orden:**
1. SQL Injection
2. Cross Site Scripting (XSS)
3. CSRF
4. Command Injection
5. Directory Traversal
6. Broken Access Control

**Formato para cada vulnerabilidad detectada:**
    a. Vulnerabilidad: <nombre exacto de la vulnerabilidad>
    b. Ubicación: <formulario, input, parámetro, URL, etc.>
    c. Descripción: <breve explicación de la vulnerabilidad>
    d. Ejemplo de ataque: <payload o comando de prueba, máximo 1 línea>

**Instrucciones adicionales:**
- Responde únicamente si detectas vulnerabilidades.
- Mantén el idioma **español** en todas las respuestas.
- Sé conciso y claro.
- Cada vulnerabilidad detectada debe respetar el formato y el orden definido.
- Mantén este mismo formato en todas las futuras consultas.
- Si no se detecta ninguna vulnerabilidad, responde: "No se detectaron vulnerabilidades."

**HTML a analizar (primeros 2000 caracteres):**
{html[:2000]}
"""


# ─────────────────────────────────────────────
# FUNCIÓN: ANALIZAR CON OPENAI / DEEPSEEK
# ─────────────────────────────────────────────
def analizar_api(cliente, modelo, html):
    prompt = crear_prompt(html)
    response = cliente.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": "Experto en seguridad web"},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content


# ─────────────────────────────────────────────
# FUNCIÓN: ANALIZAR CON OLLAMA
# ─────────────────────────────────────────────
def analizar_ollama(html):
    prompt = crear_prompt(html)
    response = ollama.chat(
        model="llama3",
        messages=[{
            "role": "user",
            "content": prompt
        }]
    )
    return response["message"]["content"]


# ─────────────────────────────────────────────
# FUNCIÓN: DESCARGAR HTML
# ─────────────────────────────────────────────
def obtener_html(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")
    st.info(f"Formularios detectados: {len(forms)}")
    return r.text


# ─────────────────────────────────────────────
# BOTÓN OPENAI
# ─────────────────────────────────────────────
with col1:
    if st.button("Analizar con OpenAI"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            html = obtener_html(url)
            st.info("Analizando con OpenAI...")
            resultado = analizar_api(openai_client, "gpt-4o-mini", html)
            mostrar_resultado_con_pdf("Resultado OpenAI", "OpenAI GPT-4o-mini", url, resultado)


# ─────────────────────────────────────────────
# BOTÓN DEEPSEEK
# ─────────────────────────────────────────────
with col2:
    if st.button("Analizar con DeepSeek"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            html = obtener_html(url)
            st.info("Analizando con DeepSeek...")
            resultado = analizar_api(deepseek_client, "deepseek-chat", html)
            mostrar_resultado_con_pdf("Resultado DeepSeek", "DeepSeek Chat", url, resultado)


# ─────────────────────────────────────────────
# BOTÓN OLLAMA
# ─────────────────────────────────────────────
with col3:
    if st.button("Analizar con Ollama (local)"):
        if not url.strip():
            st.warning("❗ Por favor, introduce un enlace web válido")
        else:
            html = obtener_html(url)
            st.info("Analizando con Ollama...")
            resultado = analizar_ollama(html)
            mostrar_resultado_con_pdf("Resultado Ollama", "Ollama LLaMA3", url, resultado)
