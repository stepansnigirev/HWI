import socket
import traceback
from typing import Optional

from .ipc_message import IpcMessage


def ipc_connect(port: int) -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # we use a very short timeout for connection in this way we are very fast to enumerate (especially on Windows)
        sock.settimeout(0.5)
        sock.connect(("127.0.0.1", port))

        # If connection succeeded remove the timeout
        sock.settimeout(None)

        return sock
    except:
        return None


def ipc_read_message(sock: socket.socket) -> Optional[IpcMessage]:
    try:
        # get the type
        cmd = sock.recv(IpcMessage.get_cmd_msg_size()).decode("utf-8")
        cmd = cmd.strip().replace(" ", "")

        # get the size
        size = sock.recv(IpcMessage.get_size_msg_size()).decode("utf-8")
        size = size.strip().replace(" ", "")

        if len(size) == 0:
            return None

        # read the payload
        value = sock.recv(int(size))

        return IpcMessage(cmd, str(value.decode("utf-8")))

    except:
        print(traceback.format_exc())
        return None


def ipc_send_message(sock: socket.socket, msg: IpcMessage) -> bool:

    try:
        # serialize the type
        cmd = msg.get_cmd().ljust(IpcMessage.get_cmd_msg_size())

        # serialize the size
        size_int = len(msg.get_raw_value())
        size = str(size_int).ljust(IpcMessage.get_size_msg_size())

        # serialize the payload and send all
        complete = cmd + size + msg.get_raw_value()
        sock.sendall(str.encode(complete))
        return True
    except:
        print(traceback.format_exc())
        return False


def ipc_send_and_get_response(
    sock: socket.socket, msg: IpcMessage
) -> Optional[IpcMessage]:
    if not ipc_send_message(sock, msg):
        return None

    return ipc_read_message(sock)
