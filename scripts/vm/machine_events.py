"""Owned local QMP diagnostics: negotiate and observe, never control guest state."""
import json
import socket
import time


class MachineEvents:
    LIMIT = 256 * 1024

    def __init__(self, endpoint, directory):
        self.endpoint = str(endpoint)
        self.directory = directory
        self.listener = None
        self.channel = None
        self.log = None
        self.buffer = b""
        self.received = 0
        self.started = time.monotonic()

    def __enter__(self):
        self.log = (self.directory / "qmp-events.jsonl").open("w")
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.endpoint)
        self.listener.listen(1)
        self.listener.settimeout(10)
        return self

    def connect(self):
        self.channel, _ = self.listener.accept()
        self.channel.setblocking(False)
        self.drain()

    def request(self, command, identifier):
        # Deliberately no generic guest-command or monitor-command interface.
        if command not in ["qmp_capabilities", "query-status", "query-cpus-fast"]:
            raise RuntimeError("Non-observation QMP command refused")
        self.channel.settimeout(1)
        try:
            self.channel.sendall(json.dumps({"execute": command, "id": identifier}).encode() + b"\n")
        finally:
            self.channel.setblocking(False)

    def drain(self):
        if self.channel is None:
            return
        while True:
            try:
                data = self.channel.recv(65536)
            except (BlockingIOError, ConnectionResetError):
                return
            if not data:
                return
            self.received += len(data)
            if self.received > self.LIMIT:
                raise RuntimeError("Oversized QMP observation")
            self.buffer += data
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                event = json.loads(line)
                self.log.write(json.dumps({"host_seconds": round(time.monotonic() - self.started, 3),
                                           "qmp": event}) + "\n")
                self.log.flush()
                if "QMP" in event:
                    self.request("qmp_capabilities", "capabilities")
                elif event.get("id") == "capabilities":
                    if "error" in event:
                        raise RuntimeError("QMP capability negotiation failed")
                    self.request("query-status", "initial-status")
                    self.request("query-cpus-fast", "initial-cpus")
                elif event.get("event") == "WAKEUP":
                    self.request("query-status", "resumed-status")
                    self.request("query-cpus-fast", "resumed-cpus")

    def __exit__(self, *_):
        if self.channel:
            self.channel.close()
        if self.listener:
            self.listener.close()
        if self.log:
            self.log.close()
