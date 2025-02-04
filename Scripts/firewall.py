import os
import requests
from prometheus_client import start_http_server, Gauge
from scapy.all import sniff
import time

# Definición de métricas de Prometheus
traffic_total = Gauge('traffic_total_packets', 'Total de paquetes procesados')
threats_detected = Gauge('threats_detected', 'Amenazas detectadas por el modelo')
prediction_time = Gauge('prediction_time_seconds', 'Tiempo promedio de predicción (segundos)')

# URL del modelo de TensorFlow Serving
MODEL_URL = "http://tf_model_serving:8501/v1/models/firewall_model:predict"


# Diccionario para almacenar información de los flujos
flows = {}

# Inicializar un flujo
def initialize_flow(flow_key):
    return {
        "Protocol": 0,
        "Flow Duration": 0,
        "Total Fwd Packets": 0,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 0,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Lengths": [],
        "Bwd Packet Lengths": [],
        "Timestamps": [],
        "Packets": [],  # Inicializar la lista de paquetes
        "Flags": {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0},
        "Fwd IATs": [],
        "Bwd IATs": [],
    }

# Función para extraer características básicas del paquete
def extract_basic_features(packet):
    if packet.haslayer("IP"):
        return {
            "Protocol": packet["IP"].proto,
            "Source IP": packet["IP"].src,
            "Destination IP": packet["IP"].dst,
            "Packet Length": len(packet),
            "Timestamp": packet.time
        }
    return None

# Función para actualizar el flujo con las características del paquete
def update_flow(packet):
    if not packet.haslayer("IP"):
        return None

    # Clave del flujo (IP origen, IP destino, protocolo)
    flow_key = (packet["IP"].src, packet["IP"].dst, packet["IP"].proto)
    if flow_key not in flows:
        flows[flow_key] = initialize_flow(flow_key)

    flow = flows[flow_key]
    flow["Protocol"] = packet["IP"].proto
    flow["Timestamps"].append(packet.time)
    flow.setdefault("Packets", []).append(packet)

    # Diferenciar entre forward y backward
    if packet["IP"].src == flow_key[0]:  # Forward
        flow["Total Fwd Packets"] += 1
        flow["Total Length of Fwd Packets"] += len(packet)
        flow["Fwd Packet Lengths"].append(len(packet))
        if len(flow["Timestamps"]) > 1:
            flow["Fwd IATs"].append(flow["Timestamps"][-1] - flow["Timestamps"][-2])
    else:  # Backward
        flow["Total Backward Packets"] += 1
        flow["Total Length of Bwd Packets"] += len(packet)
        flow["Bwd Packet Lengths"].append(len(packet))
        if len(flow["Timestamps"]) > 1:
            flow["Bwd IATs"].append(flow["Timestamps"][-1] - flow["Timestamps"][-2])

    # Actualizar flags TCP
    if packet.haslayer("TCP"):
        flags = packet["TCP"].flags
        if flags & 0x01:  # FIN
            flow["Flags"]["FIN"] += 1
        if flags & 0x02:  # SYN
            flow["Flags"]["SYN"] += 1
        if flags & 0x04:  # RST
            flow["Flags"]["RST"] += 1
        if flags & 0x08:  # PSH
            flow["Flags"]["PSH"] += 1
        if flags & 0x10:  # ACK
            flow["Flags"]["ACK"] += 1
        if flags & 0x20:  # URG
            flow["Flags"]["URG"] += 1

    # Actualizar duración del flujo
    flow["Flow Duration"] = flow["Timestamps"][-1] - flow["Timestamps"][0]
    return flow

    

# Función para calcular características avanzadas y generar vector
def vectorize_flow_features(flow):
    flow["Flow Bytes/s"] = (flow["Total Length of Fwd Packets"] + flow["Total Length of Bwd Packets"]) / (flow["Flow Duration"] + 1e-6)
    flow["Flow Packets/s"] = (flow["Total Fwd Packets"] + flow["Total Backward Packets"]) / (flow["Flow Duration"] + 1e-6)
    # Calcular métricas de Flow IAT
    if len(flow["Timestamps"]) > 1:
        iat_list = [flow["Timestamps"][i] - flow["Timestamps"][i - 1] for i in range(1, len(flow["Timestamps"]))]
        flow["Flow IAT Mean"] = sum(iat_list) / len(iat_list) if iat_list else 0
        flow["Flow IAT Std"] = (sum((x - flow["Flow IAT Mean"]) ** 2 for x in iat_list) / len(iat_list)) ** 0.5 if iat_list else 0
        flow["Flow IAT Max"] = max(iat_list, default=0)
        flow["Flow IAT Min"] = min(iat_list, default=0)
    else:
        # Si hay menos de 2 timestamps, los valores serán 0
        flow["Flow IAT Mean"] = 0
        flow["Flow IAT Std"] = 0
        flow["Flow IAT Max"] = 0
        flow["Flow IAT Min"] = 0
    flow["Fwd Header Length"] = 0  # Fwd Header Length
    flow["Bwd Header Length"] = 0 
    flow = calculate_packet_rates(flow)
    flow = calculate_additional_metrics(flow)
    flow["CWE Flag Count"] = 0
    flow["ECE Flag Count"] = 0
    # Forward IAT
    flow["Fwd IAT Total"] = sum(flow["Fwd IATs"])
    flow["Fwd IAT Mean"] = flow["Fwd IAT Total"] / len(flow["Fwd IATs"]) if flow["Fwd IATs"] else 0
    flow["Fwd IAT Std"] = (sum((x - flow["Fwd IAT Mean"]) ** 2 for x in flow["Fwd IATs"]) / len(flow["Fwd IATs"])) ** 0.5 if flow["Fwd IATs"] else 0
    flow["Fwd IAT Max"] = max(flow["Fwd IATs"], default=0)
    flow["Fwd IAT Min"] = min(flow["Fwd IATs"], default=0)
    flow["Bwd IAT Total"] = sum(flow["Bwd IATs"])
    flow["Bwd IAT Mean"] = flow["Bwd IAT Total"] / len(flow["Bwd IATs"]) if flow["Bwd IATs"] else 0
    flow["Bwd IAT Std"] = (sum((x - flow["Bwd IAT Mean"]) ** 2 for x in flow["Bwd IATs"]) / len(flow["Bwd IATs"])) ** 0.5 if flow["Bwd IATs"] else 0
    flow["Bwd IAT Max"] = max(flow["Bwd IATs"], default=0)
    flow["Bwd IAT Min"] = min(flow["Bwd IATs"], default=0)
    fwd_lengths = flow["Fwd Packet Lengths"]
    bwd_lengths = flow["Bwd Packet Lengths"]
    all_lengths = fwd_lengths + bwd_lengths
    flow["Min Packet Length"] = min(all_lengths, default=0)
    flow["Max Packet Length"] = max(all_lengths, default=0)
    flow["Packet Length Mean"] = sum(all_lengths) / len(all_lengths) if all_lengths else 0
    flow["Packet Length Std"] = (sum((x - flow["Packet Length Mean"]) ** 2 for x in all_lengths) / len(all_lengths)) ** 0.5 if all_lengths else 0
    flow["Packet Length Variance"] = (sum((x - flow["Packet Length Mean"]) ** 2 for x in all_lengths) / len(all_lengths)) if all_lengths else 0
    flow["FIN Flag Count"] = flow["Flags"]["FIN"]
    flow["SYN Flag Count"] = flow["Flags"]["SYN"]
    flow["RST Flag Count"] = flow["Flags"]["RST"]
    flow["PSH Flag Count"] = flow["Flags"]["PSH"]
    flow["ACK Flag Count"] = flow["Flags"]["ACK"]
    flow["URG Flag Count"] = flow["Flags"]["URG"]
    flow["Avg Fwd Segment Size"] = flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"] if flow["Total Fwd Packets"] else 0
    flow["Avg Bwd Segment Size"] = flow["Total Length of Bwd Packets"] / flow["Total Backward Packets"] if flow["Total Backward Packets"] else 0
    flow["Subflow Fwd Packets"] = flow["Total Fwd Packets"]
    flow["Subflow Fwd Bytes"] = flow["Total Length of Fwd Packets"]
    flow["Subflow Bwd Packets"] = flow["Total Backward Packets"]
    flow["Subflow Bwd Bytes"] = flow["Total Length of Bwd Packets"]



    vector = [
flow["Protocol"],  # Protocol
flow["Flow Duration"],  # Flow Duration
flow["Total Fwd Packets"],  # Total Fwd Packets
flow["Total Backward Packets"],  # Total Backward Packets
flow["Total Length of Fwd Packets"],  # Total Length of Fwd Packets
flow["Total Length of Bwd Packets"],  # Total Length of Bwd Packets
max(flow["Fwd Packet Lengths"], default=0),  # Fwd Packet Length Max
min(flow["Fwd Packet Lengths"], default=0),  # Fwd Packet Length Min
sum(flow["Fwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"]) if flow["Fwd Packet Lengths"] else 0,  # Fwd Packet Length Mean
(sum((x - sum(flow["Fwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"])) ** 2 for x in flow["Fwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"])) ** 0.5 if flow["Fwd Packet Lengths"] else 0,  # Fwd Packet Length Std
max(flow["Bwd Packet Lengths"], default=0),  # Bwd Packet Length Max
min(flow["Bwd Packet Lengths"], default=0),  # Bwd Packet Length Min
sum(flow["Bwd Packet Lengths"]) / len(flow["Bwd Packet Lengths"]) if flow["Bwd Packet Lengths"] else 0,  # Bwd Packet Length Mean
(sum((x - sum(flow["Bwd Packet Lengths"]) / len(flow["Bwd Packet Lengths"])) ** 2 for x in flow["Bwd Packet Lengths"]) / len(flow["Bwd Packet Lengths"])) ** 0.5 if flow["Bwd Packet Lengths"] else 0,  # Bwd Packet Length Std
flow["Flow Bytes/s"],  # Flow Bytes/s
flow["Flow Packets/s"],  # Flow Packets/s
flow["Flow IAT Mean"],  # Flow IAT Mean
flow["Flow IAT Std"],  # Flow IAT Std
flow["Flow IAT Max"],  # Flow IAT Max
flow["Flow IAT Min"],  # Flow IAT Min
flow["Fwd IAT Total"],  # Fwd IAT Total
flow["Fwd IAT Mean"],  # Fwd IAT Mean
flow["Fwd IAT Std"],  # Fwd IAT Std
flow["Fwd IAT Max"],  # Fwd IAT Max
flow["Fwd IAT Min"],  # Fwd IAT Min
flow["Bwd IAT Total"],  # Bwd IAT Total
flow["Bwd IAT Mean"],  # Bwd IAT Mean
flow["Bwd IAT Std"],  # Bwd IAT Std
flow["Bwd IAT Max"],  # Bwd IAT Max
flow["Bwd IAT Min"],  # Bwd IAT Min
flow["Fwd Header Length"],  # Fwd Header Length
flow["Bwd Header Length"],  # Bwd Header Length
flow["Fwd Packets/s"],  # Fwd Packets/s
flow["Bwd Packets/s"],  # Bwd Packets/s
min(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"], default=0),  # Min Packet Length
max(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"], default=0),  # Max Packet Length
sum(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) if flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"] else 0,  # Packet Length Mean
(sum((x - (sum(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]))) ** 2 for x in flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"])) ** 0.5 if flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"] else 0,  # Packet Length Std
# Packet Length Variance
(sum((x - (sum(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]))) ** 2 for x in flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"]) / len(flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"])) if flow["Fwd Packet Lengths"] + flow["Bwd Packet Lengths"] else 0,
flow["FIN Flag Count"],  # FIN Flag Count
flow["SYN Flag Count"],  # SYN Flag Count
flow["RST Flag Count"],  # RST Flag Count
flow["PSH Flag Count"],  # PSH Flag Count
flow["ACK Flag Count"],  # ACK Flag Count
flow["URG Flag Count"],  # URG Flag Count
flow["CWE Flag Count"],  # CWE Flag Count
flow["ECE Flag Count"],  # ECE Flag Count
flow["Down/Up Ratio"],  # Down/Up Ratio
flow["Average Packet Size"],  # Average Packet Size
flow["Avg Fwd Segment Size"],  # Avg Fwd Segment Size
flow["Avg Bwd Segment Size"],  # Avg Bwd Segment Size
flow["Fwd Avg Bytes/Bulk"],  # Fwd Avg Bytes/Bulk
flow["Subflow Fwd Packets"],  # Subflow Fwd Packets
flow["Subflow Fwd Bytes"],  # Subflow Fwd Bytes
flow["Subflow Bwd Packets"],  # Subflow Bwd Packets
flow["Subflow Bwd Bytes"],  # Subflow Bwd Bytes
flow["act_data_pkt_fwd"],  # act_data_pkt_fwd
flow["min_seg_size_forward"],  # min_seg_size_forward
flow["Active Mean"],  # Active Mean
flow["Active Std"],  # Active Std
flow["Active Max"],  # Active Max
flow["Active Min"],  # Active Min
flow["Idle Mean"],  # Idle Mean
flow["Idle Std"],  # Idle Std
flow["Idle Max"],  # Idle Max
flow["Idle Min"],  # Idle Min
]
    print(vector)
    return vector

	

def calculate_packet_rates(flow):
    flow["Flow Duration"] = flow["Timestamps"][-1] - flow["Timestamps"][0] if len(flow["Timestamps"]) > 1 else 0    
    flow["Fwd Packets/s"] = flow["Total Fwd Packets"] / (flow["Flow Duration"] + 1e-6)
    flow["Bwd Packets/s"] = flow["Total Backward Packets"] / (flow["Flow Duration"] + 1e-6)
    return flow
  
def calculate_additional_metrics(flow):
    # Down/Up Ratio
    flow["Down/Up Ratio"] = flow["Total Backward Packets"] / (flow["Total Fwd Packets"] + 1)

    # Average Packet Size
    total_packets = flow["Total Fwd Packets"] + flow["Total Backward Packets"]
    flow["Average Packet Size"] = (flow["Total Length of Fwd Packets"] + flow["Total Length of Bwd Packets"]) / total_packets if total_packets > 0 else 0

    # Avg Fwd Segment Size
    flow["Avg Fwd Segment Size"] = flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"] if flow["Total Fwd Packets"] > 0 else 0

    # Avg Bwd Segment Size
    flow["Avg Bwd Segment Size"] = flow["Total Length of Bwd Packets"] / flow["Total Backward Packets"] if flow["Total Backward Packets"] > 0 else 0
    flow["Fwd Avg Bytes/Bulk"] = flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"] if flow["Total Fwd Packets"] > 0 else 0
    
    # Asumiendo que un paquete de datos no tiene flags de control (como ACK)
    flow["act_data_pkt_fwd"] = sum(1 for pkt in flow["Packets"] if pkt.haslayer("TCP") and not pkt["TCP"].flags & 0x10)  # Excluye los ACKs
    flow["min_seg_size_forward"] = min(flow["Fwd Packet Lengths"], default=0)


    # Subflow Fwd Packets and Bytes
    flow["Subflow Fwd Packets"] = flow["Total Fwd Packets"]
    flow["Subflow Fwd Bytes"] = flow["Total Length of Fwd Packets"]
    
    # Subflow Bwd Packets and Bytes
    flow["Subflow Bwd Packets"] = flow["Total Backward Packets"]
    flow["Subflow Bwd Bytes"] = flow["Total Length of Bwd Packets"]
    
    # Active/Idle Metrics (using Timestamps)
    active_periods = [flow["Timestamps"][i] - flow["Timestamps"][i - 1] for i in range(1, len(flow["Timestamps"]))]
    flow["Active Mean"] = sum(active_periods) / len(active_periods) if active_periods else 0
    flow["Active Std"] = (sum((x - flow["Active Mean"]) ** 2 for x in active_periods) / len(active_periods)) ** 0.5 if active_periods else 0
    flow["Active Max"] = max(active_periods, default=0)
    flow["Active Min"] = min(active_periods, default=0)
    
    idle_periods = [flow["Timestamps"][i] - flow["Timestamps"][i - 1] for i in range(1, len(flow["Timestamps"]))]
    flow["Idle Mean"] = sum(idle_periods) / len(idle_periods) if idle_periods else 0
    flow["Idle Std"] = (sum((x - flow["Idle Mean"]) ** 2 for x in idle_periods) / len(idle_periods)) ** 0.5 if idle_periods else 0
    flow["Idle Max"] = max(idle_periods, default=0)
    flow["Idle Min"] = min(idle_periods, default=0)
    
    return flow



# Función para predecir y bloquear IPs
def predict_and_block(flow, flow_key):
    vector = vectorize_flow_features(flow)
    
    # Medir el tiempo de predicción
    start_time = time.time()
    
    # Realizar la predicción utilizando el modelo TensorFlow
    response = requests.post(MODEL_URL, json={"instances": [vector]})
    prediction = response.json()["predictions"][0][0]

    # Actualizar el tiempo de predicción
    prediction_time.set(time.time() - start_time)

    # Si se detecta tráfico malicioso, bloquear la IP de origen
    if prediction > 0.5:
        ip_to_block = flow_key[0]  # IP de origen
        # os.system(f"iptables -A INPUT -s {ip_to_block} -j DROP")
        print(f"IP {ip_to_block} bloqueada. Predicción: {prediction}")
    else:
        print(f"Tráfico permitido de {flow_key[0]}. Predicción: {prediction}")

    # Incrementar la métrica de amenazas detectadas
    threats_detected.inc()

# Función para procesar paquetes en tiempo real
def process_packet(packet):
    flow = update_flow(packet)
    if flow:
        flow_key = (packet["IP"].src, packet["IP"].dst, packet["IP"].proto)
        predict_and_block(flow, flow_key)

# Iniciar servidor HTTP para métricas
start_http_server(8000)
        
# Capturar tráfico de red
print("Iniciando captura de tráfico...")
sniff(filter="ip", prn=process_packet)
