import requests
import os
from scapy.all import sniff

# URL del modelo
MODEL_URL = "http://localhost:8501/v1/models/firewall_model:predict"

# Función para enviar datos al modelo y bloquear IPs
def predict_and_block(ip, data):
    # Enviar características al modelo
    response = requests.post(MODEL_URL, json={"instances": [data]})
    prediction = response.json()["predictions"][0][0]

    # Si la predicción es mayor a 0.5, bloquear IP
    if prediction > 0.5:
       # os.system(f"iptables -A INPUT -s {ip} -j DROP")
        print(f"IP {ip} bloqueada. (Predicción: {prediction})")
    else:
        print(f"IP {ip} permitida. (Predicción: {prediction})")

# Función para procesar paquetes capturados
def process_packet(packet):
    if packet.haslayer("IP"):
        ip = packet["IP"].src  # IP de origen
        features = extract_features(packet)  # Define esta función para extraer características
        predict_and_block(ip, features)

# Capturar paquetes en tiempo real
sniff(filter="ip", prn=process_packet)


ip_address = "192.116.1.100"
# Características del tráfico
traffic_features = [6.0, 55.0, 1.0, 1.0, 2.0, 6.0, 2.0, 2.0, 2.0, 0.0, 6.0, 6.0, 6.0, 0.0, 145454.5455, 36363.63636, 55.0, 0.0, 55.0, 55.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 24.0, 20.0, 18181.81818, 18181.81818, 2.0, 6.0, 3.333333333, 2.309401077, 5.333333333, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 5.0, 2.0, 6.0, 0.0, 1.0, 2.0, 1.0, 6.0, 0.0, 24.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
predict_and_block(ip_address, traffic_features)
