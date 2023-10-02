
import socket
import errno
import sys

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from pathlib import Path

ENCODING = 'utf-8'

MSG_SIZE_HEADER_LENGTH = 10
OPERATION_HEADER_LENGTH = 1

REGISTER_KEY_OP_CODE = 0
SEND_MESSAGE_OP_CODE = 1

IP = "127.0.0.1"
PORT = 1234

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))
client_socket.setblocking(False)

my_username = input("Username: ")


def pad_string(string: str):
    how_much_pad = len(string) % 8
    if how_much_pad != 0:
        how_much_pad = 8 - how_much_pad

    return string.ljust(how_much_pad, ' ')


def get_user_key(user: str):
    try:
        return Path(f"{user}_key").read_text().encode(ENCODING)
    except FileNotFoundError as _:
        print("Cannot find key")
        return False


def create_operation_data(code):
    operation_bytes = f"{code}".encode(ENCODING)
    operation_header = f"{len(operation_bytes):<{OPERATION_HEADER_LENGTH}}".encode(ENCODING)
    return operation_bytes, operation_header


def register_client(sock: socket, username: str):
    operation_bytes, operation_header = create_operation_data(REGISTER_KEY_OP_CODE)

    username_bytes = username.encode(ENCODING)
    username_header = f"{len(username_bytes):<{MSG_SIZE_HEADER_LENGTH}}".encode(ENCODING)

    sock.send(operation_header + operation_bytes + username_header + username_bytes)


register_client(client_socket, my_username)


def get_msg_len(sock: socket):
    msg_header = sock.recv(MSG_SIZE_HEADER_LENGTH)
    if not len(msg_header):
        print('Connection closed by the server')
        sys.exit()
    msg_len = int(msg_header.decode('utf-8').strip())
    return msg_len


def handle_io_exception(exception: IOError):
    if exception.errno != errno.EAGAIN and exception.errno != errno.EWOULDBLOCK:
        print('Reading error: {}'.format(str(exception)))
        sys.exit()


while True:

    # Wait for user to input a message
    message = input(f'{my_username} sends... > ')
    recipient = input('who is recipient? > ')

    # If message is not empty - send it
    if message and recipient:
        op_bytes, op_header = create_operation_data(SEND_MESSAGE_OP_CODE)

        recipient_bytes = recipient.encode(ENCODING)
        recipient_header = f"{len(recipient_bytes):<{MSG_SIZE_HEADER_LENGTH}}".encode(ENCODING)

        message = pad(message.encode(ENCODING), 16)

        user_key = get_user_key(recipient)

        if user_key is False:
            print("you cannot send message to this user, no such key")
            continue

        message = DES.new(user_key, DES.MODE_ECB).encrypt(message)

        message_header = f"{len(message):<{MSG_SIZE_HEADER_LENGTH}}".encode(ENCODING)

        client_socket.send(op_header + op_bytes + recipient_header + recipient_bytes + message_header + message)

    try:
        while True:
            sender_name_length = get_msg_len(client_socket)
            sender_name = client_socket.recv(sender_name_length).decode(ENCODING)

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            received_message_header = client_socket.recv(MSG_SIZE_HEADER_LENGTH)
            received_message_length = int(received_message_header.decode(ENCODING).strip())
            received_message = client_socket.recv(received_message_length)

            key_to_decrypt = get_user_key(sender_name)
            received_message = unpad(DES.new(key_to_decrypt, DES.MODE_ECB).decrypt(received_message), 16).decode(
                ENCODING)

            # Print message
            print(f'{sender_name} > {received_message}')

    except IOError as e:
        handle_io_exception(e)
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()