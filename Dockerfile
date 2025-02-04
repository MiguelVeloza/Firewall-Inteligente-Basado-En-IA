# Usa una imagen base ligera de Python
FROM python:3.9-slim

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Instalar las dependencias del sistema necesarias para libpcap y scapy
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libpcap-dev \
    tcpdump \
    iproute2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copiar el script principal y dependencias al contenedor
COPY Scripts/firewall.py .
COPY requirements.txt .

# Instalar las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Exponer un puerto (si es necesario para APIs o servicios)
EXPOSE 8080

# Comando para ejecutar el script
CMD ["python", "firewall.py"]
