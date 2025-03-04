# harmony_xdr2splunk
Send incidentes from Harmony XDR XPR to Splunk HEC

## README

### Overview
This script retrieves security incident data from the Check Point XDR API and sends high-severity incidents to Splunk using the HTTP Event Collector (HEC). It performs authentication, fetches recent incidents, and sends the relevant data to Splunk.

### Features
- Authenticates with the Check Point XDR API.
- Retrieves security incidents within a specified time range.
- Formats timestamps in ISO 8601 format.
- Sends incidents with high or critical severity to Splunk.
- Handles request errors and API responses gracefully.

### Requirements
- Python 3.x
- `requests` library (install using `pip install requests`)

### Configuration
#### Splunk Settings
- Update the `splunk_url` variable with your Splunk HTTP Event Collector (HEC) endpoint.
- Replace `splunk_token` with your valid Splunk HEC authentication token.

#### Check Point XDR API Credentials
- Update the `auth_data` dictionary with your `clientId`, `accessKey`, and `ck` values.

### Usage
Run the script without parameters to fetch the latest incidents:
```sh
python xdr.py
```

The script will:
1. Authenticate with the Check Point API.
2. Retrieve recent security incidents.
3. If incidents have high or critical severity, fetch their full details and send them to Splunk.

---

### Descripción
Este script obtiene datos de incidentes de seguridad desde la API de Check Point XDR y envía incidentes de alta severidad a Splunk utilizando el HTTP Event Collector (HEC). Realiza la autenticación, obtiene incidentes recientes y envía la información relevante a Splunk.

### Características
- Se autentica en la API de Check Point XDR.
- Recupera incidentes de seguridad dentro de un rango de tiempo específico.
- Formatea las marcas de tiempo en formato ISO 8601.
- Envía incidentes con severidad alta o crítica a Splunk.
- Maneja errores en las solicitudes y respuestas de la API.

### Requisitos
- Python 3.x
- Biblioteca `requests` (instalar con `pip install requests`)

### Configuración
#### Configuración de Splunk
- Actualiza la variable `splunk_url` con la URL del HTTP Event Collector (HEC) de Splunk.
- Reemplaza `splunk_token` con tu token de autenticación de HEC válido.

#### Credenciales de la API de Check Point XDR
- Modifica el diccionario `auth_data` con los valores correctos de `clientId`, `accessKey` y `ck`.

### Uso
Ejecuta el script sin parámetros para obtener los incidentes más recientes:
```sh
python xdr.py
```

El script realizará los siguientes pasos:
1. Autenticarse en la API de Check Point.
2. Obtener los incidentes recientes de seguridad.
3. Si hay incidentes con severidad alta o crítica, obtener sus detalles completos y enviarlos a Splunk.

