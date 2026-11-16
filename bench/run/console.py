"""Scriptable, timestamped serial console over libvirt's raw TCP serial socket.

Every byte received is logged with the host monotonic + wall clock time of
arrival, which lets the boot benchmark split boot time into phases
(firmware/loader, kernel, userspace) without trusting guest clocks.
"""
import re
import socket
import threading
import time


class Console:
    def __init__(self, port, logpath=None, host="127.0.0.1", connect_timeout=30):
        deadline = time.time() + connect_timeout
        while True:
            try:
                self.sock = socket.create_connection((host, port), timeout=2)
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.05)
        self.sock.settimeout(None)
        self.buf = ""
        self.pos = 0
        self.lines = []  # (wall_time, line)
        self.chunks = []  # (wall_time, buffer offset after the chunk)
        self._partial = ""
        self.lock = threading.Condition()
        self.log = open(logpath, "a", buffering=1) if logpath else None
        self.closed = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                data = b""
            if not data:
                with self.lock:
                    self.closed = True
                    self.lock.notify_all()
                return
            now = time.time()
            text = data.decode("utf-8", "replace")
            with self.lock:
                self.buf += text
                self.chunks.append((now, len(self.buf)))
                self._partial += text
                while "\n" in self._partial:
                    line, self._partial = self._partial.split("\n", 1)
                    line = line.rstrip("\r")
                    self.lines.append((now, line))
                    if self.log:
                        self.log.write(f"{now:.3f} {line}\n")
                self.lock.notify_all()

    def expect(self, pattern, timeout=60):
        """Wait for regex in output after the current position; return match."""
        rx = re.compile(pattern, re.M)
        deadline = time.time() + timeout
        with self.lock:
            while True:
                m = rx.search(self.buf, self.pos)
                if m:
                    self.pos = m.end()
                    return m
                left = deadline - time.time()
                if left <= 0 or self.closed:
                    tail = self.buf[-600:]
                    raise TimeoutError(f"timeout waiting for {pattern!r}; tail:\n{tail}")
                self.lock.wait(min(left, 0.5))

    def time_of(self, pattern):
        """Host arrival time of the first match of pattern in the raw stream."""
        import bisect
        m = re.search(pattern, self.buf, re.M)
        if not m:
            return None
        i = bisect.bisect_left([c[1] for c in self.chunks], m.end())
        return self.chunks[min(i, len(self.chunks) - 1)][0]

    def send(self, text):
        self.sock.sendall(text.encode())

    def sendline(self, text=""):
        self.send(text + "\r")

    def drain(self):
        with self.lock:
            self.pos = len(self.buf)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        if self.log:
            self.log.close()
