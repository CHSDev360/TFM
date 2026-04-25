import streamlit as st
import json
import pandas as pd
import ollama

from bs4 import BeautifulSoup

# Selenium
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# ---------------------------
# CONFIG
# ---------------------------
st.set_page_config(page_title="AI Vulnerability Scanner (Local)", layout="wide")

st.title("🔐 AI Web Vulnerability Scanner - LOCAL (Ollama)")
st.write("Análisis de vulnerabilidades usando IA local")

url = st.text_input("🌐 Introduce una URL")


# ---------------------------
# PROMPT PRO
# ---------------------------
def crear_prompt(contenido):
    return f"""
Analista de seguridad web: detecta vulnerabilidades en el código HTML/JS proporcionado.

VULNERABILIDADES A BUSCAR:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. CSRF (Cross-Site Request Forgery)
4. Command Injection
5. Directory Traversal

NIVELES DE CLASIFICACIÓN:
- "confirmada": Evidencia directa en código (concatenación SQL, innerHTML sin escape, formularios sin token CSRF, exec() con input, rutas con ../)
- "sospecha": Indicios sin evidencia completa (inputs sin validación visible, funciones peligrosas sin contexto)

FORMATO JSON (obligatorio):
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
- Campo "nivel" obligatorio

CONTENIDO:
{contenido}
"""


# ---------------------------
# SELENIUM (HTML dinámico + extracción avanzada)
# ---------------------------
def obtener_html_selenium(url):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    try:
        driver.get(url)

        # Espera inteligente
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        html = driver.page_source
        
        # Extraer recursos adicionales
        recursos = {
            "html": html,
            "scripts_inline": [],
            "scripts_externos": [],
            "formularios": [],
            "endpoints": set(),
            "archivos": []
        }
        
        # Scripts inline - extraer contenido inmediatamente
        try:
            scripts_inline = driver.find_elements(By.TAG_NAME, "script")
            for script in scripts_inline:
                try:
                    contenido = script.get_attribute("innerHTML")
                    if contenido and contenido.strip():
                        recursos["scripts_inline"].append(contenido[:1000])
                except:
                    continue
        except Exception as e:
            st.warning(f"No se pudieron extraer scripts inline: {e}")
        
        # Scripts externos - extraer src inmediatamente
        try:
            scripts_externos = driver.find_elements(By.CSS_SELECTOR, "script[src]")
            for script in scripts_externos:
                try:
                    src = script.get_attribute("src")
                    if src:
                        recursos["scripts_externos"].append(src)
                except:
                    continue
        except Exception as e:
            st.warning(f"No se pudieron extraer scripts externos: {e}")
        
        # Formularios completos - extraer datos inmediatamente
        try:
            formularios = driver.find_elements(By.TAG_NAME, "form")
            for form in formularios:
                try:
                    form_data = {
                        "action": form.get_attribute("action") or "N/A",
                        "method": form.get_attribute("method") or "GET",
                        "inputs": []
                    }
                    
                    inputs = form.find_elements(By.TAG_NAME, "input")
                    for inp in inputs:
                        try:
                            form_data["inputs"].append({
                                "name": inp.get_attribute("name"),
                                "type": inp.get_attribute("type"),
                                "id": inp.get_attribute("id")
                            })
                        except:
                            continue
                    
                    recursos["formularios"].append(form_data)
                except:
                    continue
        except Exception as e:
            st.warning(f"No se pudieron extraer formularios: {e}")
        
        # Mapear endpoints (links) - extraer href inmediatamente
        try:
            links = driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href and href.startswith("http"):
                        recursos["endpoints"].add(href)
                except:
                    continue
        except Exception as e:
            st.warning(f"No se pudieron extraer endpoints: {e}")
        
        # Buscar endpoints en scripts (fetch, axios, XMLHttpRequest)
        import re
        for script_content in recursos["scripts_inline"]:
            try:
                endpoints_en_js = re.findall(r'["\']([/\w\-\.]+/api/[/\w\-\.]*)["\']', script_content)
                recursos["endpoints"].update(endpoints_en_js)
                
                fetch_calls = re.findall(r'fetch\(["\']([^"\']+)["\']', script_content)
                recursos["endpoints"].update(fetch_calls)
                
                axios_calls = re.findall(r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']', script_content)
                # Extraer solo las URLs (segundo grupo del match)
                recursos["endpoints"].update([url for _, url in axios_calls])
            except:
                continue
        
        # Archivos descargables - extraer href inmediatamente
        try:
            archivos_links = driver.find_elements(By.CSS_SELECTOR, "a[href$='.pdf'], a[href$='.zip'], a[href$='.doc'], a[href$='.xls'], a[href$='.docx'], a[href$='.xlsx']")
            for archivo in archivos_links:
                try:
                    href = archivo.get_attribute("href")
                    if href:
                        recursos["archivos"].append(href)
                except:
                    continue
        except Exception as e:
            st.warning(f"No se pudieron extraer archivos descargables: {e}")
        
        recursos["endpoints"] = list(recursos["endpoints"])[:50]  # Limitar
        
        return recursos

    except Exception as e:
        st.error(f"❌ Error Selenium: {e}")
        return None

    finally:
        driver.quit()


# ---------------------------
# EXTRAER CONTEXTO
# ---------------------------
def extraer_contexto(recursos):
    """Procesa los recursos extraídos por Selenium"""
    soup = BeautifulSoup(recursos["html"], "html.parser")
    
    # Información adicional del HTML
    meta_tags = soup.find_all("meta")
    headers_info = {meta.get("name", meta.get("property", "")): meta.get("content", "") 
                    for meta in meta_tags if meta.get("content")}
    
    return {
        "formularios": recursos["formularios"],
        "scripts_externos": recursos["scripts_externos"],
        "scripts_inline_count": len(recursos["scripts_inline"]),
        "endpoints": recursos["endpoints"],
        "archivos": recursos["archivos"],
        "meta_info": headers_info
    }


# ---------------------------
# OLLAMA
# ---------------------------
def analizar_ollama(contenido):
    prompt = crear_prompt(contenido)

    response = ollama.chat(
        model="qwen3.5:4b",
        messages=[{
            "role": "user",
            "content": prompt
        }]
    )

    return response["message"]["content"]


# ---------------------------
# PARSE JSON
# ---------------------------
def parsear_resultado(resultado):
    try:
        inicio = resultado.find("[")
        fin = resultado.rfind("]") + 1
        limpio = resultado[inicio:fin]

        data = json.loads(limpio)
        return pd.DataFrame(data)

    except Exception as e:
        st.error(f"⚠️ Error parseando JSON: {e}")
        st.code(resultado)
        return pd.DataFrame()


# ---------------------------
# BOTÓN
# ---------------------------
if st.button("🚀 Analizar"):

    if not url.strip():
        st.warning("Introduce una URL válida")

    else:
        recursos = obtener_html_selenium(url)

        if recursos:
            contexto = extraer_contexto(recursos)

            # Preparar contenido enriquecido para análisis
            contenido = f"""
URL: {url}

HTML (primeros 2000 caracteres):
{recursos['html'][:2000]}

FORMULARIOS DETECTADOS ({len(contexto['formularios'])}):
{json.dumps(contexto['formularios'], indent=2, ensure_ascii=False)[:1500]}

SCRIPTS EXTERNOS ({len(contexto['scripts_externos'])}):
{json.dumps(contexto['scripts_externos'][:10], indent=2, ensure_ascii=False)}

SCRIPTS INLINE: {contexto['scripts_inline_count']} detectados
Muestra del primero:
{recursos['scripts_inline'][0][:800] if recursos['scripts_inline'] else 'N/A'}

ENDPOINTS MAPEADOS ({len(contexto['endpoints'])}):
{json.dumps(contexto['endpoints'][:20], indent=2, ensure_ascii=False)}

ARCHIVOS DESCARGABLES ({len(contexto['archivos'])}):
{json.dumps(contexto['archivos'][:10], indent=2, ensure_ascii=False)}
"""

            # Mostrar métricas en UI
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📝 Formularios", len(contexto['formularios']))
            with col2:
                st.metric("📦 Scripts", len(contexto['scripts_externos']) + contexto['scripts_inline_count'])
            with col3:
                st.metric("🔗 Endpoints", len(contexto['endpoints']))
            with col4:
                st.metric("📄 Archivos", len(contexto['archivos']))
            
            # Expandibles con detalles
            with st.expander("� Ver Formularios Detectados"):
                st.json(contexto['formularios'])
            
            with st.expander("🔍 Ver Endpoints Mapeados"):
                st.json(contexto['endpoints'][:30])
            
            with st.expander("� Ver Scripts Externos"):
                st.json(contexto['scripts_externos'][:20])

            with st.expander("📎 Ver Archivos Descargables"):
                if contexto['archivos']:
                    for archivo in contexto['archivos']:
                        nombre = archivo.split('/')[-1].split('?')[0]
                        st.write(f"📄 **{nombre}**")
                        st.caption(archivo)
                else:
                    st.info("No se encontraron archivos descargables")

            with st.spinner("Analizando con IA local..."):
                resultado = analizar_ollama(contenido)

            df = parsear_resultado(resultado)

            # ---------------------------
            # GRID RESUMEN
            # ---------------------------
            VULNERABILIDADES = [
                "SQL Injection",
                "Cross-Site Scripting (XSS)",
                "Cross-Site Request Forgery (CSRF)",
                "Command Injection",
                "Directory Traversal",
            ]

            st.subheader("🛡️ Resumen de Vulnerabilidades")

            # Clasificar vulnerabilidades: confirmadas vs sospechas
            confirmadas = set()
            sospechas = set()
            
            if not df.empty and "vulnerabilidad" in df.columns:
                # Priorizar campo "nivel" si existe
                if "nivel" in df.columns:
                    for idx, row in df.iterrows():
                        v = str(row["vulnerabilidad"])
                        nivel = str(row["nivel"]).lower()
                        
                        for vuln in VULNERABILIDADES:
                            if vuln.lower() in v.lower():
                                if nivel == "confirmada":
                                    confirmadas.add(vuln)
                                elif nivel == "sospecha":
                                    sospechas.add(vuln)
                else:
                    # Fallback: analizar descripción
                    for idx, row in df.iterrows():
                        v = str(row["vulnerabilidad"]).lower()
                        desc = str(row.get("descripcion", "")).lower()
                        
                        es_sospecha = any(palabra in desc for palabra in [
                            "sospecha", "posible", "potencial", "puede", "podría", 
                            "probable", "indicios", "débil", "ambiguo", "sin confirmar"
                        ])
                        
                        for vuln in VULNERABILIDADES:
                            if vuln.lower() in v:
                                if es_sospecha:
                                    sospechas.add(vuln)
                                else:
                                    confirmadas.add(vuln)

            cols = st.columns(len(VULNERABILIDADES))
            for col, vuln in zip(cols, VULNERABILIDADES):
                with col:
                    if vuln in confirmadas:
                        icon = "❌"
                        color = "#f8d7da"  # rojo
                        estado = "Detectada"
                    elif vuln in sospechas:
                        icon = "⚠️"
                        color = "#fff3cd"  # amarillo
                        estado = "Sospecha"
                    else:
                        icon = "✅"
                        color = "#d4edda"  # verde
                        estado = "Seguro"
                    
                    st.markdown(
                        f"""
                        <div style="background:{color};border-radius:8px;padding:16px;text-align:center;">
                            <div style="font-size:2rem;">{icon}</div>
                            <div style="color:black;font-size:0.8rem;font-weight:600;margin-top:6px;">{vuln}</div>
                            <div style="font-size:0.7rem;color:#666;margin-top:4px;">{estado}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            st.markdown("---")

            if df.empty:
                st.success("✅ No se detectaron vulnerabilidades")
            else:
                st.subheader("📊 Detalle de Vulnerabilidades")

                st.dataframe(df, use_container_width=True)

                st.download_button(
                    "⬇️ Descargar CSV",
                    df.to_csv(index=False),
                    "vulnerabilidades.csv",
                    "text/csv"
                )