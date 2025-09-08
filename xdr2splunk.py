import requests
import configparser
from datetime import datetime, timedelta, timezone
import urllib3
import json

# Desactiva advertencias por certificados SSL inválidos (sólo si es absolutamente necesario)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lista de IPs consideradas peligrosas
IPS_PELIGROSAS = ["172.16.11.40", "172.16.11.41", "10.1.5.13", "10.3.22.255"]

# Texto por defecto del comentario para la función original
ORIGINAL_COMMENT_TEXT = "Security Test"

# Cargar configuración desde el archivo externo
config = configparser.ConfigParser()
try:
    if not config.read("config.properties"):
        print("❌ Error: No se pudo encontrar o leer el archivo 'config.properties'. Asegúrate de que exista y sea legible.")
        exit()
except configparser.Error as e:
    print(f"❌ Error al parsear 'config.properties': {e}")
    exit()

# Constantes para el menú
SEVERIDADES_ORDENADAS = ['informational', 'low', 'medium', 'high', 'critical']
COMMENT_TEXT_GESTIONADO = "Security Test - gestionado por script"
STATUS_CLOSE_HANDLED = "close - handled"

# --- FUNCIONES DE UTILIDAD ---
def format_datetime(date):
    """Formatea un objeto datetime a la cadena ISO 8601 requerida por la API."""
    return date.astimezone(timezone.utc).isoformat(timespec='seconds').replace("+00:00", "Z")

def send_to_splunk(event):
    """Envía un evento a Splunk."""
    try:
        splunk_url = config["SPLUNK"]["url"]
        splunk_token = config["SPLUNK"]["token"]
    except KeyError as e:
        print(f"❌ Error: Falta la clave {e} en la sección [SPLUNK] del archivo 'config.properties'.")
        return False
        
    headers = {
        "Authorization": f"Splunk {splunk_token}",
        "Content-Type": "application/json"
    }
    payload = {"event": event}
    try:
        response = requests.post(splunk_url, json=payload, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            print("✅ Evento enviado a Splunk con éxito.")
            return True
        else:
            print(f"❌ Error al enviar a Splunk: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión con Splunk: {e}")
        return False

def get_incident_details(token, incident_uuid):
    """Obtiene los detalles de un incidente específico por su UUID."""
    url = f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents/{incident_uuid}"
    headers = {"accept": "application/json", "Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Error al obtener detalles del incidente {incident_uuid}: {response.status_code} - {response.text}")
            return {}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión al obtener detalles del incidente {incident_uuid}: {e}")
        return {}

def comentar_ticket(token, incident_display_id, comment_text, user_email):
    """Añade un comentario a un ticket."""
    url = f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents/{incident_display_id}/comments"
    headers = {"accept": "application/json", "Authorization": f"Bearer {token}"}
    payload = {
        "text": comment_text,
        "userEmail": user_email
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code in [200, 201]:
            print(f"📝 Comentario añadido al incidente con Display ID {incident_display_id}.")
            return True
        else:
            print(f"⚠️ Error al añadir comentario al incidente con Display ID {incident_display_id}: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión al añadir comentario al incidente {incident_display_id}: {e}")
        return False

def close_ticket(token, incident_uuid):
    """Cierra un ticket por su UUID."""
    url = f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents/{incident_uuid}"
    headers = {"accept": "application/json", "Authorization": f"Bearer {token}"}
    payload = {"status": STATUS_CLOSE_HANDLED, "followUp": False} 
    try:
        response = requests.put(url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"✅ Incidente {incident_uuid} cerrado correctamente.")
            return True
        else:
            print(f"❌ Error al cerrar incidente {incident_uuid}: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión al cerrar incidente {incident_uuid}: {e}")
        return False

def ip_in_assets_indicators(data, ip_list):
    """Verifica si alguna IP de la lista está presente en los assets o indicadores de un incidente."""
    assets = data.get("data", {}).get("assets", [])
    indicators = data.get("data", {}).get("indicators", [])
    for obj in assets + indicators:
        if obj.get("value") in ip_list:
            return True
    return False

def imprimir_info_basica_incidente(incident):
    """Imprime la información básica de un incidente en un formato legible."""
    display_id = incident.get("display_id", "N/A")
    description = incident.get("summary", "Sin descripción")
    updated_at = incident.get("updated_at", "Fecha no disponible")
    severity = incident.get("severity", "No especificada").lower()
    status = incident.get("status", "N/A")
    uuid = incident.get("id", "N/A")
    print(f"  Display ID: {display_id:<15} UUID: {uuid:<38} Severidad: {severity.capitalize():<12} Estado: {status:<15} Actualizado: {updated_at:<25} Resumen: {description}")

# --- AUTENTICACIÓN ---
def autenticar_xdr():
    """Realiza la autenticación y devuelve el token y user_email."""
    print("🔐 Realizando autenticación XDR...")
    try:
        auth_url = config["XDR"]["auth_url"]
        client_id_val = config["XDR"]["client_id"]
        access_key = config["XDR"]["access_key"]
        ck = config["XDR"]["ck"]
        user_email = config["XDR"]["userEmail"]
    except KeyError as e:
        print(f"❌ Error: Falta la clave {e} en la sección [XDR] del archivo 'config.properties'.")
        return None, None

    auth_headers = {"accept": "application/json", "Content-Type": "application/json"}
    auth_data = {
        "clientId": client_id_val,
        "accessKey": access_key,
        "ck": ck
    }
    try:
        auth_response = requests.post(auth_url, json=auth_data, headers=auth_headers, timeout=10)
        print(f"📡 Código de respuesta autenticación: {auth_response.status_code}")
        if auth_response.status_code != 200:
            print("❌ Error en la autenticación XDR:", auth_response.status_code)
            print("🔴 Respuesta:", auth_response.text)
            return None, None

        auth_json = auth_response.json()
        token = auth_json.get("data", {}).get("token")
        expires = auth_json.get("data", {}).get("expires")
        if not token:
            print("❌ Error: No se pudo obtener el token de la respuesta de autenticación.")
            return None, None
        
        print(f"✅ Token obtenido correctamente. Expira el: {expires}")
        return token, user_email
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión durante la autenticación XDR: {e}")
        return None, None

# --- OBTENCIÓN DE INCIDENTES ---
def obtener_incidentes_api(token, hours_ago, limit=10000, offset=0, status_filter=None):
    """Obtiene una lista de incidentes desde la API XDR."""
    if not token:
        return []

    now = datetime.now(timezone.utc)
    from_date_dt = now - timedelta(hours=hours_ago)
    to_date_dt = now
    from_date = format_datetime(from_date_dt)
    to_date = format_datetime(to_date_dt)

    print(f"📥 Solicitando lista de incidentes (últimas {hours_ago} horas desde {from_date})...")
    
    base_url = "https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents"
    params = {
        "filterBy": "updatedAt", 
        "limit": limit,
        "offset": offset,
        "from": from_date,
        "to": to_date
    }
    if status_filter and isinstance(status_filter, list):
        params["status"] = ",".join(status_filter)

    headers = {"accept": "application/json", "Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=20)
        print(f"📡 Código de respuesta incidentes: {response.status_code}")
        if response.status_code == 200:
            response_json = response.json()
            incidents = response_json.get("data", {}).get("incidents", [])
            print(f"🔎 Número de incidentes encontrados: {len(incidents)}")
            return incidents
        else:
            print(f"❌ Error al obtener incidentes: {response.status_code} - {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión al obtener incidentes: {e}")
        return []

# --- FUNCIONES PARA LAS OPCIONES DEL MENÚ ---

def opcion_filtrar_por_severidad(token, global_hours_ago):
    """Permite al usuario filtrar y mostrar incidentes por una severidad mínima."""
    if not token:
        print("⛔ No se puede continuar sin token de autenticación.")
        return

    print("\n--- Mostrar Incidentes por Nivel de Severidad Mínima ---")
    print("Severidades disponibles:", ", ".join(s.capitalize() for s in SEVERIDADES_ORDENADAS))
    
    severidad_minima_str = input("Introduce la severidad mínima a mostrar (ej: Medium): ").lower()
    if severidad_minima_str not in SEVERIDADES_ORDENADAS:
        print(f"❌ Severidad '{severidad_minima_str}' no válida. Inténtalo de nuevo.")
        return

    severidad_minima_idx = SEVERIDADES_ORDENADAS.index(severidad_minima_str)
    
    incidentes = obtener_incidentes_api(token, hours_ago=global_hours_ago)

    if not incidentes:
        print("ℹ️ No se encontraron incidentes para filtrar en el período especificado.")
        return

    print(f"\n🔎 Incidentes con severidad '{severidad_minima_str.capitalize()}' o superior:")
    count = 0
    for inc in incidentes:
        current_severity_str = inc.get("severity", "").lower()
        if current_severity_str in SEVERIDADES_ORDENADAS:
            current_severity_idx = SEVERIDADES_ORDENADAS.index(current_severity_str)
            if current_severity_idx >= severidad_minima_idx:
                imprimir_info_basica_incidente(inc)
                count += 1
    if count == 0:
        print(f"ℹ️ No se encontraron incidentes con severidad '{severidad_minima_str.capitalize()}' o superior en el período especificado.")

def opcion_cerrar_tickets_por_severidad(token, user_email, global_hours_ago):
    """Permite al usuario cerrar tickets abiertos por severidad (todas las severidades, sin filtro IP)."""
    if not token or not user_email:
        print("⛔ No se puede continuar sin token o user_email.")
        return

    print("\n--- Gestionar Cierre de Tickets por Severidad (TODOS los incidentes abiertos) ---")
    print("Severidades disponibles:", ", ".join(s.capitalize() for s in SEVERIDADES_ORDENADAS))
    
    severidad_maxima_str = input("Introduce la severidad MÁXIMA a cerrar (ej: Medium para cerrar Informational, Low y Medium): ").lower()
    if severidad_maxima_str not in SEVERIDADES_ORDENADAS:
        print(f"❌ Severidad '{severidad_maxima_str}' no válida. Inténtalo de nuevo.")
        return

    confirmacion = input(f"⚠️ ¿Estás seguro de que quieres cerrar TODOS los tickets con severidad '{severidad_maxima_str.capitalize()}' e inferiores ('new' o 'in progress') encontrados en las últimas {global_hours_ago} horas, añadiendo el comentario '{COMMENT_TEXT_GESTIONADO}'? (s/N): ").lower()
    if confirmacion != 's':
        print("🚫 Operación cancelada.")
        return

    severidad_maxima_idx = SEVERIDADES_ORDENADAS.index(severidad_maxima_str)
    
    incidentes_abiertos = obtener_incidentes_api(token, hours_ago=global_hours_ago, status_filter=['new', 'in progress'], limit=10000)

    if not incidentes_abiertos:
        print("ℹ️ No se encontraron incidentes abiertos o en progreso para cerrar en el período especificado.")
        return

    print(f"\n🛠️ Procesando cierre de incidentes hasta severidad '{severidad_maxima_str.capitalize()}'...")
    cerrados_count = 0
    for inc in incidentes_abiertos:
        current_severity_str = inc.get("severity", "").lower()
        status = inc.get("status", "").lower()
        
        if current_severity_str in SEVERIDADES_ORDENADAS and status in ["new", "in progress"]:
            current_severity_idx = SEVERIDADES_ORDENADAS.index(current_severity_str)
            if current_severity_idx <= severidad_maxima_idx:
                incident_uuid = inc.get("id")
                incident_display_id = inc.get("display_id")
                
                if not incident_uuid or not incident_display_id:
                    print(f"⏭️ Omitiendo incidente por falta de ID o Display ID: {inc.get('summary')}")
                    continue

                print(f"➡️  Procesando Display ID: {incident_display_id}, Severidad: {current_severity_str.capitalize()}")
                
                comentado = comentar_ticket(token, incident_display_id, COMMENT_TEXT_GESTIONADO, user_email)
                if comentado:
                    cerrado = close_ticket(token, incident_uuid)
                    if cerrado:
                        cerrados_count += 1
                else:
                    print(f"⚠️ No se pudo comentar el ticket {incident_display_id}, no se procederá a cerrar.")
                print("-" * 30)
                
    print(f"\n✅ Operación completada. Se procesaron para cierre {cerrados_count} tickets.")

def opcion_cerrar_tickets_por_ip(token, user_email, global_hours_ago):
    """Permite al usuario cerrar tickets abiertos que contengan IPs peligrosas."""
    if not token or not user_email:
        print("⛔ No se puede continuar sin token o user_email.")
        return

    print("\n--- Cerrar Tickets con IP Peligrosa ---")
    confirmacion = input(f"⚠️ ¿Estás seguro de que quieres cerrar TODOS los tickets 'new' o 'in progress' encontrados en las últimas {global_hours_ago} horas, que contengan alguna IP de la lista de IPs peligrosas ('{', '.join(IPS_PELIGROSAS)}') añadiendo el comentario '{COMMENT_TEXT_GESTIONADO}'? (s/N): ").lower()
    if confirmacion != 's':
        print("🚫 Operación cancelada.")
        return

    incidentes_abiertos = obtener_incidentes_api(token, hours_ago=global_hours_ago, status_filter=['new', 'in progress'], limit=10000)

    if not incidentes_abiertos:
        print("ℹ️ No se encontraron incidentes abiertos o en progreso para cerrar en el período especificado.")
        return

    print(f"\n🛠️ Procesando cierre de incidentes con IPs peligrosas...")
    cerrados_count = 0
    for inc in incidentes_abiertos:
        status = inc.get("status", "").lower()
        if status in ["new", "in progress"]:
            incident_uuid = inc.get("id")
            incident_display_id = inc.get("display_id")
            
            if not incident_uuid or not incident_display_id:
                print(f"⏭️ Omitiendo incidente por falta de ID o Display ID: {inc.get('summary')}")
                continue

            incident_details = get_incident_details(token, incident_uuid)
            if not incident_details or not incident_details.get("data"):
                print(f"⚠️ No se pudieron obtener detalles para {incident_display_id}, se omite su procesamiento.")
                continue

            tiene_ip_peligrosa = ip_in_assets_indicators(incident_details, IPS_PELIGROSAS)
            
            if tiene_ip_peligrosa:
                print(f"➡️  Procesando Display ID: {incident_display_id}, IP Peligrosa Detectada: SÍ")
                
                comentado = comentar_ticket(token, incident_display_id, "Security Test", user_email)
                if comentado:
                    cerrado = close_ticket(token, incident_uuid)
                    if cerrado:
                        cerrados_count += 1
                else:
                    print(f"⚠️ No se pudo comentar el ticket {incident_display_id}, no se procederá a cerrar.")
                print("-" * 30)
                
    print(f"\n✅ Operación completada. Se procesaron para cierre {cerrados_count} tickets con IPs peligrosas.")


def opcion_ver_detalle_incidente(token):
    """Permite al usuario ver los detalles completos de un incidente por su UUID."""
    if not token:
        print("⛔ No se puede continuar sin token.")
        return

    print("\n--- Ver Detalle de un Incidente ---")
    incident_uuid_input = input("Introduce el UUID del incidente a detallar: ").strip()
    
    if not incident_uuid_input: 
        print("❌ UUID del incidente no puede estar vacío.")
        return

    print(f"🔍 Obteniendo detalles para el incidente UUID: {incident_uuid_input}...")
    detalles = get_incident_details(token, incident_uuid_input)

    if detalles and detalles.get("data"):
        print("\n--- Detalles del Incidente ---")
        print(json.dumps(detalles.get("data"), indent=4, ensure_ascii=False))
    elif detalles:
        print("\n--- Respuesta de la API (inesperada) ---")
        print(json.dumps(detalles, indent=4, ensure_ascii=False))
    else:
        print(f"ℹ️ No se pudieron obtener detalles para el incidente UUID: {incident_uuid_input} o el incidente no existe.")


# --- FUNCIÓN ORIGINAL (Adaptada para usar el rango de tiempo global) ---
def get_incidents_original(token_existente, user_email_existente, global_hours_ago, limit=10000, offset=0):
    """Ejecuta el proceso original de recolección, envío a Splunk y cierre de incidentes."""
    token, user_email = token_existente, user_email_existente
    print("ℹ️ Usando token y user_email existentes para 'get_incidents_original'.")

    now = datetime.now(timezone.utc)
    from_date_dt = now - timedelta(hours=global_hours_ago)
    to_date_dt = now
    from_date = format_datetime(from_date_dt)
    to_date = format_datetime(to_date_dt)

    print("🕒 Iniciando recolección de incidentes (proceso original)...")
    print(f"📅 Rango de fechas: Desde {from_date} (últimas {global_hours_ago} horas) hasta {to_date}")
    
    incidentes = obtener_incidentes_api(token, hours_ago=global_hours_ago, limit=limit, offset=offset)

    if not incidentes:
        print("ℹ️ No se encontraron incidentes en el rango temporal especificado para el proceso original.")
        return

    count_high, count_critical, count_closed_peligrosas = 0, 0, 0

    print(f"\n{'Fecha actualización':<25} {'Display ID':<15} {'Descripción':<50} {'Severidad':<10} {'Estado':<15} {'IP Peligrosa'}")
    print("=" * 130)

    for incident in incidentes:
        status = incident.get("status", "").lower()
        if status not in ["new", "in progress"]:
            continue

        if incident.get("is_prevented", False):
            continue

        incident_uuid = incident.get("id")
        display_id = incident.get("display_id", "N/A")
        description = incident.get("summary", "Sin descripción")
        updated_at = incident.get("updated_at", "Fecha no disponible")
        severity = incident.get("severity", "No especificada").lower()

        if not incident_uuid or not display_id:
            print(f"⏭️ Omitiendo incidente por falta de ID o Display ID: {description}")
            continue

        incident_details = get_incident_details(token, incident_uuid)
        if not incident_details or not incident_details.get("data"):
            print(f"⚠️ No se pudieron obtener detalles para {display_id}, se omite su procesamiento avanzado.")
            print(f"{updated_at:<25} {display_id:<15} {description:<50} {severity.capitalize():<10} {status:<15} {'Desconocida'}")
            continue

        tiene_ip_peligrosa = ip_in_assets_indicators(incident_details, IPS_PELIGROSAS)
        print(f"{updated_at:<25} {display_id:<15} {description:<50} {severity.capitalize():<10} {status:<15} {str(tiene_ip_peligrosa)}")

        if severity in ["high", "critical"]:
            print(f"📤 Enviando {display_id} a Splunk...")
            enviado = send_to_splunk(incident_details.get("data"))
            if enviado:
                if severity == "high": count_high += 1
                elif severity == "critical": count_critical += 1

        if tiene_ip_peligrosa:
            print(f"🗨️ Añadiendo comentario a {display_id}...")
            comentado = comentar_ticket(token, display_id, ORIGINAL_COMMENT_TEXT, user_email)
            if comentado:
                print(f"🔒 Cerrando incidente {display_id} (UUID: {incident_uuid})...")
                cerrado = close_ticket(token, incident_uuid)
                if cerrado:
                    count_closed_peligrosas += 1

    print("\n📘 Resumen de la ejecución (proceso original):")
    print("="*50)
    print(f"Período evaluado: Desde {from_date} hasta {to_date}")
    print(f"{'Incidentes High enviados a Splunk':<35} | {count_high:>5}")
    print(f"{'Incidentes Critical enviados a Splunk':<35} | {count_critical:>5}")
    print(f"{'Incidentes cerrados por IPs peligrosas':<35} | {count_closed_peligrosas:>5}")
    print("="*50)

# --- PUNTO DE ENTRADA ---
def menu_inicio():
    """Función principal que maneja el menú de interacción con el usuario."""
    # Autenticación inicial
    token, user_email = autenticar_xdr()

    if not token or not user_email:
        print("\n❌ Falló la autenticación XDR o falta userEmail en config. No se puede continuar.")
        print("Verifique 'config.properties' y la conectividad.")
        return

    # Petición global del rango de tiempo
    global_hours_ago = 24 # Valor por defecto
    while True:
        try:
            user_input = input(f"\n¿Cuántas horas hacia atrás quieres buscar incidentes por defecto (24 horas)? Introduce un número o presiona Enter para usar el valor por defecto: ")
            if user_input == "":
                break
            hours = int(user_input)
            if hours <= 0:
                print("❌ Por favor, introduce un número positivo de horas.")
            else:
                global_hours_ago = hours
                break
        except ValueError:
            print("❌ Entrada no válida. Por favor, introduce un número entero.")
    
    print(f"✅ Se buscarán incidentes en las últimas {global_hours_ago} horas por defecto.")

    while True:
        print("\n--- Menú Principal de Gestión de Incidentes XDR ---")
        print(f"Periodo de búsqueda por defecto: Útimas {global_hours_ago} horas.")
        print("a) Mostrar incidentes por nivel de severidad mínima")
        print("b) Cerrar tickets (todas las severidades, sin filtro IP)")
        print("c) Cerrar tickets (solo IPs peligrosas)")
        print("d) Ver detalles de incidente (requiere UUID)")
        print("e) Ejecutar proceso original de 'get_incidents'")
        print("s) Salir")

        opcion = input("Selecciona una opción: ").lower()

        if opcion == 'a':
            opcion_filtrar_por_severidad(token, global_hours_ago)
        elif opcion == 'b':
            opcion_cerrar_tickets_por_severidad(token, user_email, global_hours_ago)
        elif opcion == 'c':
            opcion_cerrar_tickets_por_ip(token, user_email, global_hours_ago)
        elif opcion == 'd':
            opcion_ver_detalle_incidente(token)
        elif opcion == 'e':
            print("\n--- Ejecutando Proceso Original 'get_incidents' ---")
            get_incidents_original(token_existente=token, user_email_existente=user_email, global_hours_ago=global_hours_ago)
        elif opcion == 's':
            print("👋 Saliendo del programa.")
            break
        else:
            print("❌ Opción no válida. Por favor, intenta de nuevo.")

if __name__ == "__main__":
    menu_inicio()
