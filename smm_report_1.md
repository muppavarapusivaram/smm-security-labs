# Lab 1: Proving the Invisibility of Firmware Execution from the OS

**Research Series: SMM/SMRAM Security Analysis**  
**Author:** MUPPAVARAPU SIVARAM  
**Institution:** KL University Vijayawada  
**ID:** 2300030447  
**Date:** December 2024  

---

## 1. Introduction

This report documents the first phase of an architectural investigation into Intel System Management Mode (SMM) and System Management RAM (SMRAM). The objective is to establish what the operating system can observe about firmware execution environments, and more importantly, what it cannot.

This is not an exploitation study. This is a controlled observation of architectural boundaries.

---

## 2. Lab Environment

### 2.1 Hardware Platform
- **Processor:** Intel Core i5-1235U (12th Generation, Alder Lake)
- **Architecture:** x86-64
- **System:** Real hardware (not emulated)

### 2.2 Software Environment
- **Operating System:** Arch Linux (kernel 6.x series)
- **Privilege Level:** Root access via `sudo`
- **Tools Used:** Standard Linux utilities (`/proc`, `/sys`, `dmesg`, `rdmsr`)

### 2.3 Why Real Hardware?

Emulation environments like QEMU with OVMF firmware can be configured to expose or simplify SMM behavior. Real hardware enforces actual platform security boundaries. For credible firmware security research, real hardware is essential.

---

## 3. What the OS Can See

### 3.1 Physical Memory Map

The Linux kernel maintains a map of all physical memory regions it is aware of. This is exposed via `/proc/iomem`.

**Command:**
```bash
sudo cat /proc/iomem
```

**Observed Output (excerpt):**
```
00000000-00000fff : Reserved
00001000-0009ffff : System RAM
000a0000-000bffff : PCI Bus 0000:00
000c0000-000dffff : PCI Bus 0000:00
000e0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-09bfffff : System RAM
09c00000-09ffffff : Reserved
0a000000-0a1fffff : Reserved
...
```

**Observation:**
- The kernel knows about System RAM, PCI buses, ACPI tables, and reserved regions.
- There is no entry labeled "SMRAM" or "SMM Reserved."
- The memory map is incomplete by design.

---

### 3.2 Kernel Command Line

The kernel records how it was booted, including memory reservation directives.

**Command:**
```bash
cat /proc/cmdline
```

**Observed Output (example):**
```
BOOT_IMAGE=/vmlinuz-linux root=UUID=... rw quiet
```

**Observation:**
- No `memmap=` or `reserve=` directives explicitly exclude SMRAM.
- SMRAM is hidden at a lower level—before the OS even boots.

---

### 3.3 Direct Memory Access via `/dev/mem`

Linux provides `/dev/mem`, a character device that allows raw access to physical memory. If SMRAM were visible, it would be readable here.

**Command:**
```bash
sudo dd if=/dev/mem bs=1 skip=$((0xA0000)) count=4096 2>/dev/null | xxd | head
```

**Expected Behavior:**
- If SMRAM were accessible, this would return SMM code.
- If SMRAM is protected, this will return either zeroes or garbage.

**Observed Output:**
```
00000000: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ffff ffff ffff ffff ffff ffff  ................
...
```

**Interpretation:**
- The read succeeds, but the content is `0xFF` (all bits set).
- This is a classic indicator that the read hit a protected or unmapped region.
- The CPU returned "bus-high" data instead of actual memory content.

---

### 3.4 Model-Specific Registers (MSRs)

Intel processors expose configuration and status information through MSRs. Some MSRs control SMM behavior.

**Command:**
```bash
sudo rdmsr 0x9B  # IA32_SMM_MONITOR_CTL
```

**Observed Output:**
```
0
```

**Interpretation:**
- MSR `0x9B` controls whether SMM is enabled for virtualization (dual-monitor mode).
- A value of `0` means standard SMM is active, not dual-monitor mode.
- This MSR does not reveal SMRAM location or contents.

---

### 3.5 ACPI Tables

ACPI tables describe hardware to the OS. They may reference SMI (System Management Interrupt) triggers.

**Command:**
```bash
sudo cat /sys/firmware/acpi/tables/FACP | xxd | head -n 20
```

**Observed Output (partial):**
```
00000000: 4641 4350 1401 0000 0616 496e 7465 6c00  FACP......Intel.
00000010: 416c 6465 724c 6b00 0100 0000 494e 544c  AlderLk.....INTL
...
```

**Interpretation:**
- The FACP (Fixed ACPI Description Table) contains SMI command port information.
- This tells the OS *how* to trigger an SMI, not where SMM code resides.
- ACPI does not expose SMRAM.

---

## 4. What the OS Cannot See

| **Entity**            | **Visibility from OS** | **Why**                                      |
|-----------------------|------------------------|----------------------------------------------|
| SMRAM location        | ❌ Not visible         | Protected by chipset (SMRAMC register)       |
| SMRAM contents        | ❌ Not accessible      | Reads return `0xFF` or cause faults          |
| SMM code execution    | ❌ Not observable      | No kernel traces, no performance counters    |
| SMI handler dispatch  | ❌ Not logged          | Firmware handles SMI, returns to OS silently |
| SMBASE relocation     | ❌ Not reported        | Internal CPU state during SMM setup          |

---

## 5. Why Absence of Evidence Is Evidence

The fact that SMRAM does not appear in `/proc/iomem` is not a bug—it is intentional.

### 5.1 The Chipset Controls Visibility

Intel chipsets implement a register called **SMRAMC** (System Management RAM Control). This register:
- Locks SMRAM during boot
- Prevents DMA access
- Prevents OS memory reads

Once locked, even privileged OS code cannot modify this register.

### 5.2 The CPU Enforces Access

When the CPU is not in SMM, any attempt to access SMRAM:
- Returns invalid data (`0xFF`)
- May cause a machine check exception
- Never reveals actual SMM code

This is enforced in hardware, not software.

---

## 6. Conclusion

### What Was Proven

1. The OS cannot observe SMRAM in its memory map.
2. Direct memory reads of SMRAM regions return protected data.
3. MSRs and ACPI tables reference SMI control, not SMM internals.
4. The invisibility of SMRAM is architectural, not accidental.

### Why This Matters

Firmware executes in a context the OS cannot inspect. If SMM code contains a vulnerability, the OS cannot detect it, cannot log it, and cannot mitigate it. This makes SMM a **trust boundary** that must be understood, not ignored.

### Next Steps

The next report will establish that SMM is not only hidden—it is actively running on this system.

---

## 7. References

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3
- Linux kernel documentation: `/Documentation/x86/x86_64/mm.rst`
- ACPI Specification 6.5

---

**End of Report 1**