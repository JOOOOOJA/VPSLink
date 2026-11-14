"""Loopback-only integration fixture using libssh already present on the machine."""
import ctypes as C
import hmac
import os
from pathlib import Path
import queue
import shlex
import socket
import subprocess
import sys
import threading

dll_path, host_key, client_key, drop_file = (Path(x) for x in sys.argv[1:])
load_path = os.add_dll_directory(str(dll_path.parent))
dll = C.CDLL(str(dll_path))
P, I, S = C.c_void_p, C.c_int, C.c_char_p


def bind(name, restype, *argtypes):
    fn = getattr(dll, name)
    fn.restype = restype
    fn.argtypes = argtypes
    globals()[name] = fn


for name, ret, args in [
    ("ssh_init", I, []), ("ssh_bind_new", P, []), ("ssh_new", P, []), ("ssh_free", None, [P]),
    ("ssh_bind_free", None, [P]), ("ssh_disconnect", None, [P]), ("ssh_get_error", S, [P]),
    ("ssh_pki_import_privkey_file", I, [S, S, P, P, C.POINTER(P)]),
    ("ssh_pki_import_pubkey_file", I, [S, C.POINTER(P)]), ("ssh_key_free", None, [P]),
    ("ssh_key_cmp", I, [P, P, I]), ("ssh_bind_options_set", I, [P, I, P]),
    ("ssh_bind_accept_fd", I, [P, P, C.c_size_t]), ("ssh_handle_key_exchange", I, [P]),
    ("ssh_set_auth_methods", None, [P, I]), ("ssh_message_get", P, [P]),
    ("ssh_message_type", I, [P]), ("ssh_message_subtype", I, [P]),
    ("ssh_message_auth_user", S, [P]), ("ssh_message_auth_password", S, [P]),
    ("ssh_message_auth_pubkey", P, [P]), ("ssh_message_auth_publickey_state", I, [P]),
    ("ssh_message_auth_reply_pk_ok_simple", I, [P]), ("ssh_message_auth_reply_success", I, [P, I]),
    ("ssh_message_reply_default", I, [P]), ("ssh_message_free", None, [P]),
    ("ssh_message_channel_request_open_reply_accept", P, [P]),
    ("ssh_message_channel_request_command", S, [P]), ("ssh_message_channel_request_reply_success", I, [P]),
    ("ssh_channel_read_timeout", I, [P, P, C.c_uint32, I, I]),
    ("ssh_channel_write", I, [P, P, C.c_uint32]), ("ssh_channel_free", None, [P]),
    ("ssh_channel_is_open", I, [P]), ("ssh_channel_is_eof", I, [P]),
]:
    bind(name, ret, *args)

assert ssh_init() == 0
b, host, client = ssh_bind_new(), P(), P()
assert ssh_pki_import_privkey_file(os.fsencode(host_key), None, None, None, C.byref(host)) == 0
assert ssh_bind_options_set(b, 10, host) == 0  # SSH_BIND_OPTIONS_IMPORT_KEY
assert ssh_pki_import_pubkey_file(os.fsencode(client_key), C.byref(client)) == 0


def command_io(channel, command):
    args = shlex.split(command)
    if len(args) != 4 or args[:3] != ["python3", "-u", "-c"]:
        return
    with subprocess.Popen([sys.executable, *args[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW) as proc:
        output = queue.Queue(maxsize=128)

        def collect():
            while data := proc.stdout.read1(32768):
                output.put(data)

        thread = threading.Thread(target=collect, daemon=True)
        thread.start()
        buf = C.create_string_buffer(32768)
        try:
            while ssh_channel_is_open(channel) and not ssh_channel_is_eof(channel):
                if drop_file.exists():
                    drop_file.unlink()
                    return
                while not output.empty():
                    data = output.get_nowait()
                    if ssh_channel_write(channel, data, len(data)) != len(data):
                        return
                if proc.poll() is not None and not thread.is_alive():
                    return
                n = ssh_channel_read_timeout(channel, buf, len(buf), 0, 20)
                if n > 0:
                    proc.stdin.write(buf.raw[:n])
                    proc.stdin.flush()
                elif n < 0 and n != -2:
                    return
        except (BrokenPipeError, OSError):
            pass
        finally:
            proc.kill()


def handle(sock):
    session, channel = ssh_new(), None
    try:
        if ssh_bind_accept_fd(b, session, sock.detach()) != 0 or ssh_handle_key_exchange(session) != 0:
            return
        ssh_set_auth_methods(session, 2 | 4)
        authenticated = False
        while msg := ssh_message_get(session):
            command = None
            try:
                kind, sub = ssh_message_type(msg), ssh_message_subtype(msg)
                if kind == 1 and ssh_message_auth_user(msg) == b"fixture":
                    if sub == 2 and hmac.compare_digest(ssh_message_auth_password(msg) or b"", b"fixture-password!"):
                        ssh_message_auth_reply_success(msg, 0)
                        authenticated = True
                        continue
                    if sub == 4 and ssh_key_cmp(ssh_message_auth_pubkey(msg), client, 0) == 0:
                        state = ssh_message_auth_publickey_state(msg)
                        if state == 0:
                            ssh_message_auth_reply_pk_ok_simple(msg)
                            continue
                        if state == 1:
                            ssh_message_auth_reply_success(msg, 0)
                            authenticated = True
                            continue
                if authenticated and kind == 2 and sub == 1 and channel is None:
                    channel = ssh_message_channel_request_open_reply_accept(msg)
                    continue
                if authenticated and channel and kind == 3 and sub == 2:
                    command = ssh_message_channel_request_command(msg).decode("ascii")
                    ssh_message_channel_request_reply_success(msg)
                else:
                    ssh_message_reply_default(msg)
            finally:
                ssh_message_free(msg)
            if command:
                command_io(channel, command)
                return
    finally:
        if channel:
            ssh_channel_free(channel)
        ssh_disconnect(session)
        ssh_free(session)


with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(6)
    print(listener.getsockname()[1], flush=True)
    try:
        while True:
            sock, _ = listener.accept()
            handle(sock)
    finally:
        ssh_bind_free(b)
        ssh_key_free(client)


