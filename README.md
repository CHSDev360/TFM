# 📘 README - Aplicación TFM

## 🚀 Descripción

Esta es una aplicación desarrollada con Streamlit que utiliza scraping web con Selenium y procesamiento de datos con Pandas.

---

## 📦 Requisitos previos

Antes de comenzar, asegúrate de tener instalado:

* Python 3.8 o superior
* Visual Studio Code
* pip

---

## 📂 Abrir el proyecto en Visual Studio Code

1. Abre Visual Studio Code
2. Ve a **File > Open Folder**
3. Selecciona la carpeta del proyecto

---

## 🧪 Crear entorno virtual (opcional pero recomendado)

```bash
python -m venv venv
```

Activar entorno:

* Windows:

```bash
venv\Scripts\activate
```

* Mac/Linux:

```bash
source venv/bin/activate
```

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
