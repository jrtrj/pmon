# PMON – Kernel Packet Interceptor

PMON is a Linux kernel module that intercepts outgoing IPv4 packets using the Netfilter `LOCAL_OUT` hook.

It demonstrates how user-space network activity passes through the kernel and how packets can be observed in real time.

---

When a process sends data:

```text
Process → Socket → Kernel → sk_buff → Netfilter → Network
```

PMON registers at the `LOCAL_OUT` stage and logs packets as they leave the system.

---

Install headers:
```bash
sudo apt install build-essential linux-headers-$(uname -r)
```

Build:
```bash
make
```

---


Load module:
```bash
sudo insmod pmon.ko
```
