import requests
from datetime import datetime, timedelta, timezone

def format_datetime(date):
    """Formatea la fecha en formato ISO 8601 compatible con la API."""
    return date.astimezone(timezone.utc).isoformat(timespec='seconds').replace("+00:00", "Z")

def send_to_splunk(event):
    """Envía un evento a Splunk utilizando el HTTP Event Collector (HEC). Maneja errores de conexión."""
    splunk_url = "https://http-inputs-yourcompany.splunkcloud.com/services/collector"
    splunk_token = "put_your_splunk_token_here"
    headers = {
        "Authorization": f"Splunk {splunk_token}",
        "Content-Type": "application/json"
    }
    payload = {"event": event}
    
    try:
        response = requests.post(splunk_url, json=payload, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            print("Evento enviado a Splunk con éxito.")
        else:
            print(f"Error al enviar a Splunk: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión con Splunk: {e}")

def get_incident_details(token, incident_id):
    """Obtiene los detalles completos de un incidente específico."""
    details_url = f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents/{incident_id}"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(details_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error al obtener detalles para el incidente {incident_id}: {response.status_code}")
        return {}

def get_incidents(from_date=None, to_date=None, filter_by="updatedAt", limit=5, offset=0):
    # Definir valores por defecto
    now = datetime.now(timezone.utc)
    if from_date is not None:
        from_date = format_datetime(from_date)
    if to_date is not None:
        to_date = format_datetime(to_date)
    
    # Autenticación
    auth_url = "https://cloudinfra-gw.portal.checkpoint.com/auth/external"
    auth_headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    auth_data = {
        "clientId": "put_your_client_id_here",
        "accessKey": "put_your_access_key_here",
        "ck": "externalClient01"
    }

    auth_response = requests.post(auth_url, json=auth_data, headers=auth_headers)

    # Verificar si la autenticación fue exitosa
    if auth_response.status_code == 200:
        auth_json = auth_response.json()
        token = auth_json.get("data", {}).get("token")
        expires = auth_json.get("data", {}).get("expires")
        
        if token:
            print("Token obtenido: Ok Expira el", expires)
            print("---- Últimos", limit, "resultados")
            
            # Construir la URL sin from/to si no están definidos
            xdr_url = (
                f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/api/xdr/v1/incidents?"
                f"filterBy={filter_by}&limit={limit}&offset={offset}"
            )
            
            # Agregar from y to solo si están definidos
            if from_date and to_date:
                xdr_url += f"&from={from_date}&to={to_date}"
            
            xdr_headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {token}"
            }
            
            xdr_response = requests.get(xdr_url, headers=xdr_headers)
            
            # Verificar si la solicitud fue exitosa
            if xdr_response.status_code == 200:
                response_json = xdr_response.json()
                incidents = response_json.get("data", {}).get("incidents", [])
                
                if incidents:
                    print(f"{'Display ID':<15} {'Descripción':<50} {'Fecha de actualización':<30} {'Severidad':<10}")
                    print("="*120)
                    for incident in incidents:
                        incident_id = incident.get("id", "N/A")
                        incident_display_id = incident.get("display_id", "N/A")
                        description = incident.get("summary", "Sin descripción")
                        updated_at = incident.get("updated_at", "Fecha no disponible")
                        severity = incident.get("severity", "No especificada")
                        
                        # Resaltar en rojo si la severidad es "high" o "critical"
                        severity_colored = f"\033[91m{severity}\033[0m" if severity.lower() in ["high", "critical"] else severity
                        
                        print(f"{incident_id:<15} {description:<50} {updated_at:<30} {severity_colored:<10}")
                        
                        # Si la severidad es "high" o "critical", obtener detalles completos y enviarlos a Splunk
                        if severity.lower() in ["high", "critical"]:
                            incident_details = get_incident_details(token, incident_id)
                            send_to_splunk(incident_details)
                            print ("Se envía el evento", incident_id, severity, "a Splunk")
                else:
                    print("No se encontraron incidentes recientes.")
            else:
                print("Error en la solicitud de XDR_XPR:", xdr_response.status_code)
                print(xdr_response.text)
        else:
            print("No se pudo obtener el token de autenticación.")
    else:
        print("Error en la autenticación:", auth_response.status_code)
        print(auth_response.text)

# Llamar a la función sin from y to para probar si eso resuelve el problema
get_incidents()
