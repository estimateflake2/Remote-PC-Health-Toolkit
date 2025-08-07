import socket

ports = [53, 443, 80, 22, 21, 25, 110, 143, 3389]
successfull_port = []
print ("Checking availabile port connections...")
for port in ports:
    try :
        successfull_port.append(port)
        n = socket.create_connection(("8.8.8.8", port), timeout=3)
    except :
        successfull_port.pop()

print (successfull_port)