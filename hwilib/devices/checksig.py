import base64
from typing import Dict

from hwilib.devices.checksiglib.ipc import ipc_connect, ipc_send_and_get_response
from hwilib.devices.checksiglib.ipc_message import (
    AUTHORIZE_TX,
    PING,
    SIGN_TX,
    IpcMessage,
)
from hwilib.devices.checksiglib.settings import LISTEN_PORT, PORT_RANGE

from ..errors import ActionCanceledError, DeviceConnectionError
from ..hwwclient import HardwareWalletClient
from ..serializations import PSBT


class ChecksigClient(HardwareWalletClient):
    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        # Used to know where to connect for this device
        self.port = int(path.split(":")[1])

    # Segwit V0 only
    def sign_tx(self, psbt: PSBT) -> Dict[str, str]:
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the software device"
            )

        serialized_psbt = psbt.serialize()
        data = serialized_psbt + "\n"
        msg = IpcMessage(SIGN_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("CheckSig device did not sign")

        # Return signed PSBT back
        return {"psbt": resp.get_raw_value()}

    def sign_tx_with_auth(self, psbt: PSBT, auth) -> Dict[str, str]:
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the checksig device"
            )

        serialized_psbt = psbt.serialize()
        auth_b64 = base64.b64encode(auth).decode("utf-8")
        data = serialized_psbt + "\n" + auth_b64
        msg = IpcMessage(SIGN_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("CheckSig device did not sign")

        # Return signed PSBT back
        return {"psbt": resp.get_raw_value()}

    def authorize_tx(self, message: bytes, bip32_path: str) -> bytes:
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the checksig device"
            )

        message_b64 = base64.b64encode(message).decode("utf-8")
        data = message_b64 + "\n" + bip32_path
        msg = IpcMessage(AUTHORIZE_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("CheckSig device did not sign")

        return base64.b64decode(resp.get_raw_value())

    def _sign_message(self, message: bytes, bip32_path: str) -> Dict[str, str]:
        sig = self.authorize_tx(message, bip32_path)
        signature = base64.b64encode(sig).decode("utf-8")
        return {"signature": signature}

    def sign_message(self, message: str, bip32_path: str) -> Dict[str, str]:
        m = message.encode()
        return self._sign_message(m, bip32_path)

    def close(self):
        pass


def enumerate(password=""):
    results = []

    # Loop on the range port to check listening devices
    for i in range(PORT_RANGE):
        try:
            port = LISTEN_PORT + i
            sock = ipc_connect(port)

            if sock is None:
                continue

            ping_resp = ipc_send_and_get_response(sock, IpcMessage(PING, ""))
            if ping_resp is None:
                continue

            fingerprint = ping_resp.get_raw_value()

            d_data = {}
            d_data["type"] = "checksig"
            d_data["model"] = "checksig_hwi"
            d_data["path"] = "127.0.0.1:" + str(port)
            d_data["needs_pin_sent"] = False
            d_data["needs_passphrase_sent"] = False

            d_data["fingerprint"] = fingerprint
            results.append(d_data)

            sock.close()
        except:
            continue

    return results
