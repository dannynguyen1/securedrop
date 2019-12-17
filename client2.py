import json
import getpass
import os
import socket
import selectors
import types
import time
import ssl

jsonFileName = 'securedrop2.json'
sel = selectors.DefaultSelector()


class ClientData:
    name: str
    email: str
    hashed_pass: int
    contacts: []

    def __init__(self, name, email, hashed_pass, contacts):
        self.name = name
        self.email = email
        self.hashed_pass = hashed_pass
        self.contacts = contacts


# hashing algorithm
def adler32(password):
    const_mod = 65521
    a = 1
    b = 0
    for char in password:
        a = (a + ord(char)) % const_mod
        b = (b + a) % const_mod

    return (b << 16) | a


def register_client():
    name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    pw1 = getpass.getpass(prompt='Enter Password: ')
    pw2 = getpass.getpass(prompt='Enter Password Again: ')

    if name and email and pw1 and pw2:
        hash1 = adler32(pw1)
        hash2 = adler32(pw2)
        if hash1 != hash2:
            print("The two entered passwords don't match!")
            exit(1)

        json_dict = dict()
        json_dict["name"] = name
        json_dict["email"] = email
        json_dict["hash"] = hash1
        json_dict["contacts"] = []

        with open(jsonFileName, 'w') as file:
            json.dump(json_dict, file)
            print("Thanks for registering!")

    else:
        print("At least one string you entered was empty!")
        exit(1)


def login_client(client_data):
    email = input("Enter Email Address: ")
    pw = getpass.getpass(prompt='Enter Password: ')
    return email == client_data.email and adler32(pw) == client_data.hashed_pass


def get_client_data():
    with open(jsonFileName) as file:
        jsonDB = json.load(file)
        data = ClientData(name=jsonDB["name"], email=jsonDB["email"], hashed_pass=jsonDB["hash"],
                          contacts=jsonDB["contacts"])
        return data


def connect_to_server():
    host = '127.0.0.1'
    port = 6969
    server_addr = (host, port)
    print("Attempting to connect to server: ", server_addr)

    server_cert = 'server.crt'
    client_cert = 'client.crt'
    client_key = 'client.key'

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped_socket = context.wrap_socket(s, server_side=False, server_hostname='sherron')
    wrapped_socket.setblocking(False)

    try:
        wrapped_socket.connect_ex(server_addr)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        data = types.SimpleNamespace(
            recv_total=0,
            outb=b"",
        )
        sel.register(wrapped_socket, events, data=data)

        events = sel.select(timeout=1)
        if events:
            for key, mask in events:
                return ping_server(key, bytes(client_data.email, encoding='utf8'))

        else:
            return False

    except Exception as e:
        print(e)
        return False


def ping_server(key, email):
    sock = key.fileobj
    data = key.data
    data.outb = email
    try:
        print("sending", repr(data.outb), "to server")
        sent = sock.send(data.outb)
        print("sent", repr(data.outb), "to server")
        data.outb = data.outb[sent:]
        return True
    except:
        # return False
        return True


def run_help():
    print("add -> Add a new contact")
    print("list -> List all online contacts")
    print("send -> Transfer file to contact")
    print("exit -> Exit SecureDrop")


def run_add(client_data):
    name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    contact = dict()
    contact["name"] = name
    contact["email"] = email
    client_data.contacts.append(contact)

    json_dict = dict()
    json_dict["name"] = client_data.name
    json_dict["email"] = client_data.email
    json_dict["hash"] = client_data.hashed_pass
    json_dict["contacts"] = client_data.contacts

    with open(jsonFileName, 'w') as file:
        json.dump(json_dict, file)


def main_loop(client_data):
    time_last_ping = 0

    try:
        while True:
            # check if socket is fucked
            if not sel.get_map():
                print("Selector is dead")
                break

            # check if server needs to be pinged so that it knows we are online
            if time.time() - time_last_ping > 5:
                events = sel.select(timeout=1)
                if events:
                    for key, mask in events:
                        ping_server(key, bytes(client_data.email, encoding='utf8'))
                        time_last_ping = time.time()

            text = input("securedrop> ")
            if text == '':
                continue

            if text == 'exit':
                break

            if text == 'help':
                run_help()

            if text == 'add':
                run_add(client_data)

            elif text == 'list':
                print("hello")

    except KeyboardInterrupt:
        print("caught keyboard interrupt, exiting")
    finally:
        sel.close()


if __name__ == "__main__":
    if os.path.exists(jsonFileName):
        client_data = get_client_data()
        if login_client(client_data):
            if connect_to_server():
                main_loop(client_data)
            else:
                print("Failed to connect to server :'(")

            print("Bye!")
            exit(0)

        else:
            print("Login failed")
            exit(0)

    else:
        print("No users are registered with this client.")
        decision = input("Do you want to register a new user (y/n)?")
        if str(decision) == 'y':
            register_client()

        else:
            print("Bye!")
            exit(0)
