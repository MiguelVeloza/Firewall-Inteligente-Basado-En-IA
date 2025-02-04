# 🚀 Firewall Inteligente con IA  

Este proyecto implementa un **firewall inteligente** basado en **IA y machine learning** para la detección y bloqueo de tráfico malicioso en redes domésticas. Se integra con **TensorFlow Serving**, **Prometheus** y **Grafana** para el monitoreo en tiempo real.  

## 📌 Características  
✅ Detección de amenazas cibernéticas mediante un modelo de IA entrenado con **CICIDS2017**  
✅ Bloqueo automático de tráfico malicioso con **iptables**  
✅ Monitoreo en tiempo real con **Prometheus** y **Grafana**  
✅ Desplegable mediante **Docker Compose** para fácil ejecución  

## ⚙️ Requisitos Previos  
- **Docker** y **Docker Compose** instalados  
- **Git** (opcional, para clonar el repositorio)  

## 🚀 Instalación y Ejecución  

### 1️⃣ Clonar el repositorio  
```bash
git clone https://github.com/MiguelVeloza/FirewallWithIA.git
cd FirewallWithIA
```

### 2️⃣ Construir y levantar los contenedores  
```bash
docker-compose up --build -d
```

### 3️⃣ Verificar que los contenedores estén corriendo  
```bash
docker ps
```
Deberías ver los servicios **firewall, prometheus, grafana y tensorflow serving** en ejecución.  

### 4️⃣ Acceder a las herramientas  
- **Grafana:** [http://localhost:3000](http://localhost:3000) (Usuario: `admin`, Contraseña: `admin` o la que configures)  
- **Prometheus:** [http://localhost:9090](http://localhost:9090)  
- **API del modelo IA:** [http://localhost:8501/v1/models/firewall_model:predict](http://localhost:8501/v1/models/firewall_model:predict)  

## 📊 Monitoreo con Grafana  
1. Inicia sesión en **Grafana**  
2. Añade **Prometheus** como fuente de datos (`http://prometheus:9090`)  
3. Importa el dashboard preconfigurado en `grafana_dashboard.json`  

## 🛠️ Pruebas del Firewall  
Puedes probar la detección y bloqueo ejecutando el script de prueba:  
```bash
python Scripts/test_ip.py
```
Para verificar las reglas de **iptables** en tu máquina:  
```bash
sudo iptables -L -v -n
```
## ❗ Eliminar reglas de iptables en caso de bloqueos accidentales

Si el firewall bloquea tráfico legítimo por error, puedes eliminar todas las reglas impuestas con el siguiente comando:
```bash
sudo iptables -F
```
Esto restablecerá todas las reglas de iptables, permitiendo el tráfico sin restricciones.

## 📜 Licencia  
Este proyecto está bajo la licencia **MIT**, lo que significa que puedes usarlo, modificarlo y distribuirlo libremente.  

## 👨‍💻 Autor  
- **Miguel Angel Veloza Ortiz** - [GitHub](https://github.com/MiguelVeloza)  
