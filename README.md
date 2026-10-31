# macabre

Suite de auditoría de red de **capa 2** escrita en Python con [Scapy](https://scapy.net/) y una interfaz gráfica de escritorio, pensada para Linux.

Inspirada en Yersinia, pero desarrollada desde cero (sin código GPL heredado) y orientada a:

- Construir tramas a medida (*handcrafted*) de forma sencilla.
- Ejecutar pruebas de estrés y validación de protocolos de capa 2 en laboratorios y auditorías autorizadas.
- Complementar otras herramientas como `iperf` y `hping3`.
- Ser instalable como aplicación de escritorio y, en el futuro, integrarse en distribuciones de seguridad como Kali Linux.

## Estado

🚧 Fase inicial. Sin código funcional todavía.

Hoja de ruta prevista:

1. **MVP**: interfaz gráfica con menús y submenús por tipo de ataque, con un único ataque implementado: **DHCP starvation**.
2. Ataques de capa 2 adicionales: LLDP exhaustion, CDP, manipulación de BPDU (Spanning Tree), entre otros.
3. Constructor de tramas handcrafted con vista previa.
4. Empaquetado como aplicación instalable / ejecutable.

## Uso previsto y advertencia legal

Esta herramienta genera tráfico que puede interrumpir el funcionamiento de una red (agotamiento de direcciones DHCP, inundación de tablas, cambios de topología STP, etc.).

**Úsala únicamente en redes propias o en entornos para los que tengas autorización explícita por escrito.** El autor no se responsabiliza del uso indebido.

## Requisitos (previstos)

- Linux
- Python 3.10+
- Scapy
- Privilegios de root o `CAP_NET_RAW` para enviar tramas en crudo

## Licencia

Pendiente de definir.
