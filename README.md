
# PMON – Per-Process Network Usage Tracker

PMON is a Linux kernel module that tracks how much network data each process sends.
It intercepts outgoing packets inside the kernel and records total bytes sent per PID.

---

# How It Works

When a process sends data:

```
Process → Socket → Kernel → sk_buff → Netfilter → Network
```

PMON hooks into the Netfilter `LOCAL_OUT` stage and:

* identifies the sending process
* records packet size
* maintains total bytes sent per PID

---

# Build

Install kernel headers:

```bash
sudo pacman -S linux-headers 
```

Compile:

```bash
make
```

---

# Load Module

```bash
sudo insmod pmon.ko
```

---

# Generate Traffic

Example:

```bash
curl google.com
ping 8.8.8.8
```

---

# Check Usage

```bash
cat /proc/net/pmon
```

---

# Unload

```bash
sudo rmmod pmon
```

---

