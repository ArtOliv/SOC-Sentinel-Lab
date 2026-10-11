import sys
import os
import time
import json
import datetime
import hashlib
import hmac
import base64
import urllib.request

# Configurações do Log Analytics
WORKSPACE_ID = os.environ.get("WORKSPACE_ID", "")
PRIMARY_KEY = os.environ.get("PRIMARY_KEY", "")
LOG_TYPE = "RaspberrySOC"

AUTH_LOG_PATH = "/var/log/auth.log"
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

def build_signature(workspace_id, primary_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_sign = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_sign = string_to_sign.encode('utf-8')
    decoded_key = base64.b64decode(primary_key)
    signature = base64.b64encode(hmac.new(decoded_key, bytes_to_sign, digestmod=hashlib.sha256).digest()).decode('utf-8')
    return f"SharedKey {workspace_id}:{signature}"

def post_data(body_json):
    body = json.dumps(body_json).encode('utf-8')
    rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(WORKSPACE_ID, PRIMARY_KEY, rfc1123date, content_length, 'POST', 'application/json', '/api/logs')
    url = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    headers = {
        'content-type': 'application/json',
        'Authorization': signature,
        'Log-Type': LOG_TYPE,
        'x-ms-date': rfc1123date
    }

    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except Exception as e:
        print(f"[ERRO] Falha ao enviar para o Azure: {e}", file=sys.stderr)
        return False

def main():
    print("[*] Iniciando Coletor SOC Raspberry Pi para Microsoft Sentinel...")
    # Teste de conectividade inicial
    init_event = [{
        "Hostname": os.uname().nodename,
        "Source": "AgentStartup",
        "Message": "Sensor SOC iniciado e conectado ao Azure Sentinel",
        "Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }]

    if post_data(init_event):
        print("[+] Conexão com Azure estabelecida com sucesso!")
    else:
        print("[-] Falha na autenticação com o Azure. Verifique o Workspace ID e Primary Key.")

    # Ponteiros de leitura
    auth_file = open(AUTH_LOG_PATH, 'r', errors='ignore') if os.path.exists(AUTH_LOG_PATH) else None
    suri_file = open(SURICATA_LOG_PATH, 'r', errors='ignore') if os.path.exists(SURICATA_LOG_PATH) else None

    if auth_file: auth_file.seek(0, os.SEEK_END)
    if suri_file: suri_file.seek(0, os.SEEK_END)

    while True:
        payload = []
        # Monitora Auth Log
        if auth_file:
            while True:
                line = auth_file.readline()
                
                if not line: break
                
                if any(k in line for k in ["Failed password", "Accepted", "sudo:", "session opened"]):
                    payload.append({
                        "Hostname": os.uname().nodename,
                        "Source": "AuthLog",
                        "RawMessage": line.strip(),
                        "Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    })

        # Monitora Suricata IDS
        if suri_file:
            while True:
                line = suri_file.readline()
                
                if not line: break
                
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        payload.append({
                            "Hostname": os.uname().nodename,
                            "Source": "SuricataIDS",
                            "AlertSignature": data.get("alert", {}).get("signature"),
                            "Category": data.get("alert", {}).get("category"),
                            "Severity": data.get("alert", {}).get("severity"),
                            "SrcIP": data.get("src_ip"),
                            "SrcPort": data.get("src_port"),
                            "DestIP": data.get("dest_ip"),
                            "DestPort": data.get("dest_port"),
                            "Proto": data.get("proto"),
                            "RawMessage": line.strip(),
                            "Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                        })
                except json.JSONDecodeError:
                    pass

        if payload:
            post_data(payload)

        time.sleep(1)

if __name__ == '__main__':
    main()