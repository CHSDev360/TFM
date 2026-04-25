# 📘 README - Aplicación Streamlit

## 📦 Requisitos previos

Antes de comenzar, asegúrate de tener instalado:

* Python 3.8 o superior
* Visual Studio Code
* pip
* Ollama con el modelo `qwen3.5:4b` descargado

Para instalar Ollama y descargar el modelo:

```bash
ollama pull qwen3.5:4b
```

---

## 📂 Abrir el proyecto en Visual Studio Code

1. Abre Visual Studio Code
2. Ve a **File > Open Folder**
3. Selecciona la carpeta del proyecto

---

## 📥 Instalación de dependencias

Ejecuta en la terminal:

```bash
pip install streamlit pandas ollama beautifulsoup4 selenium webdriver-manager
```

---

## ▶️ Ejecutar la aplicación

En la terminal, dentro del proyecto:

```bash
streamlit run app.py
```

Esto abrirá automáticamente la app en tu navegador.

---

## 🧰 Librerías utilizadas

* Streamlit → interfaz web
* Pandas → manejo de datos
* BeautifulSoup → scraping HTML
* Selenium → automatización web
* webdriver-manager → gestión de drivers
* Ollama → integración con modelos

---

## ⚠️ Notas

* Asegúrate de tener Google Chrome instalado para que Selenium funcione correctamente.
* `webdriver-manager` descargará automáticamente el driver necesario.
* Verifica que Ollama esté en ejecución antes de iniciar la aplicación.
