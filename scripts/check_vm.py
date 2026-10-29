#!/usr/bin/env python3
"""Run explicit offline NetworkManager/TUN acceptance in a disposable QEMU VM."""
from vm.host import main

if __name__ == "__main__":
    raise SystemExit(main())
