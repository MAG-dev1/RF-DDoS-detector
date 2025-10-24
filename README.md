# Servidor TCP con Python y Selectors

Este código implementa un **servidor TCP concurrente** en Python utilizando el módulo
`selectors`. El servidor escucha conexiones entrantes y actúa como un **echo server**, es
decir, devuelve al cliente exactamente los datos que recibe.

---

## Funcionamiento

1. **Inicio del servidor**  
   - Se crea un socket TCP en `localhost:8080`.  
   - Se configura en modo no bloqueante.  
   - Se registra en el selector para esperar eventos de lectura (`EVENT_READ`).

2. **Aceptación de conexiones** (`accept_wrapper`)  
   - Cuando llega un cliente, se acepta la conexión.  
   - El socket del cliente se pone en modo no bloqueante.  
   - Se registra en el selector con los eventos de lectura y escritura.  

3. **Servicio de conexión** (`service_connection`)  
   - **Lectura (`EVENT_READ`)**:  
     - Si el cliente envía datos, se almacenan en un buffer (`data.outb`).  
     - Si no hay datos (cliente cerró la conexión), se cierra el socket.  
   - **Escritura (`EVENT_WRITE`)**:  
     - Si hay datos en el buffer, se envían de vuelta al cliente.  
     - El mensaje enviado es exactamente lo que el cliente mandó.  

---

## Ejemplo de flujo

1. Cliente se conecta al servidor.  
2. Cliente envía: `b"Hola"`.  
3. Servidor responde: `b"Hola"`.  
4. Si el cliente cierra la conexión, el servidor libera el socket.  

---

## Ejecución

```bash
python server.py
