# FTP Server (Proyecto Simple)

Servidor y cliente FTP básico implementado en Python usando sockets, con soporte para múltiples clientes mediante threads, consola administrativa y transferencia de archivos por un canal de datos separado.

## Características

- Autenticación simple por usuario/contraseña en diccionario `users` 
- Comandos básicos: listar, cd, descargar, subir, salir  
- Consola del servidor con comandos: list, kick, exit  
- Soporte para múltiples clientes usando hilos  
- Transferencia binaria de archivos por socket dedicado  

## Ejecución

Servidor:

```
python3 ftp_server.py server
```

Cliente:

```
python3 ftp_client.py client <server-ip>
```

## Propósito

Proyecto educativo para practicar uso de sockets, comunicación por códigos en Python.
