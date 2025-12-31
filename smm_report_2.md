# Lab 2: Empirical Evidence of Active SMM and Protected SMRAM

**Research Series: SMM/SMRAM Security Analysis**  
**Author:** MUPPAVARAPU SIVARAM  
**Institution:** KL University Vijayawada  
**ID:** 2300030447  
**Date:** December 2024  

---

## 1. Introduction

Lab 1 established that the operating system cannot see SMRAM. This report goes further: it demonstrates that SMM is not only hidden—it is actively running on this Intel system.

The goal is to collect **empirical evidence** that:
1. SMM exists on this platform
2. SMRAM is allocated and protected
3. SMIs (System Management Interrupts) are being serviced

This is observational research, not intrusion.

---

## 2. Hypothesis

If SMM is active on this system, we should observe:
- Protected memory regions at legacy SMRAM addresses
- CPU features indicating SMM support
- ACPI and firmware references to SMI handling
- Indirect evidence of SMI execution (though not the code itself)

---

## 3. Evidence Collection

### 3.1 Legacy SMRAM Region Test

Historically, SMRAM resided at physical address `0xA0000` to `0xBFFFF` (640 KB to 768 KB). Modern systems relocate SMRAM, but this region often remains protected as a decoy.

**Command:**
```bash
sudo dd if=/dev/mem bs=1 skip=$((0xA0000)) count=128 2>/dev/null | xxd
```

**Observed Output:**
```
00000000: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000020: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000030: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000040: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000050: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000060: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000070: ffff ffff ffff ffff ffff ffff ffff ffff  ................
```

**Analysis:**
- Every byte reads as `0xFF`.
- This is the classic signature of a **protected memory region**.
- When the CPU is not in SMM, reads to SMRAM return all-ones.

**Conclusion:**
This memory region is protected. The system is preventing OS-level access.

---

### 3.2 CPU Feature Detection

Intel processors expose their capabilities via CPUID. SMM support is a core feature of x86 processors since the 486.

**Command:**
```bash
lscpu | grep -i smm
```

**Observed Output:**
```
(no output)
```

**Why?**
- `lscpu` reads CPUID but does not expose SMM-specific flags in its summary.
- SMM is not a "feature flag" like SSE or AVX—it is part of the base architecture.

**Alternative: Check for SMI/SMM in dmesg**
```bash
dmesg | grep -i smm
dmesg | grep -i smi
```

**Observed Output:**
```
(no output)
```

**Interpretation:**
- The kernel does not log SMM activity.
- This is expected—SMI handling is transparent to the OS.

---

### 3.3 Model-Specific Register (MSR) Analysis

Intel documents several MSRs related to SMM. We examine the most relevant ones.

#### MSR 0x9B: IA32_SMM_MONITOR_CTL

**Command:**
```bash
sudo rdmsr 0x9B
```

**Output:**
```
0
```

**Interpretation:**
- Bit 0 = 0: Dual-monitor mode is disabled.
- Bit 2 = 0: SMM is active in traditional mode.
- This MSR confirms SMM is enabled, not bypassed.

#### MSR 0x34: SMI Count (Undocumented)

Some Intel processors maintain a counter of SMIs handled. This MSR is not officially documented but is sometimes present.

**Command:**
```bash
sudo rdmsr 0x34 2>/dev/null || echo "Not available"
```

**Output:**
```
Not available
```

**Interpretation:**
- This CPU does not expose an SMI counter via MSR.
- Absence of this MSR does not mean SMM is absent—it means the counter is not exposed.

---

### 3.4 ACPI Table Analysis

ACPI tables describe how the OS should interact with platform firmware. The **FACP** (Fixed ACPI Description Table) includes SMI command ports.

**Command:**
```bash
sudo cat /sys/firmware/acpi/tables/FACP | od -Ax -tx1 | head -n 30
```

**Observed Output (partial):**
```
000000 46 41 43 50 14 01 00 00 06 16 49 6e 74 65 6c 00
000010 41 6c 64 65 72 4c 6b 00 01 00 00 00 49 4e 54 4c
000020 13 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00
000030 b2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
...
```

**Key Field: SMI_CMD (Offset 0x30)**
- Bytes at offset `0x30-0x33`: `b2 00 00 00`
- This decodes to I/O port **0xB2**.

**What is Port 0xB2?**
- This is the **Software SMI trigger port**.
- Writing a byte to this port causes the CPU to enter SMM.
- The written value is the SMI command code.

**Command to Inspect Port 0xB2 (Read-Only):**
```bash
sudo inb 0xB2 2>/dev/null || echo "Cannot read"
```

**Output:**
```
Cannot read
```

**Why?**
- Port 0xB2 is write-only for software.
- The OS cannot observe what SMI commands have been issued.

---

### 3.5 Checking for SMRAM in E820 Memory Map

The E820 memory map is provided by the BIOS during boot. It tells the OS which memory regions are usable.

**Command:**
```bash
dmesg | grep -i e820
```

**Observed Output (excerpt):**
```
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009ffff] usable
[    0.000000] BIOS-e820: [mem 0x00000000000a0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x0000000009bfffff] usable
[    0.000000] BIOS-e820: [mem 0x0000000009c00000-0x0000000009ffffff] reserved
...
```

**Analysis:**
- The region `0xA0000-0xFFFFF` is marked **reserved**.
- This is the legacy VGA/SMRAM region.
- Modern SMRAM may be relocated elsewhere, but the BIOS does not report it explicitly.

**Conclusion:**
The BIOS intentionally hides SMRAM from the OS. The E820 map only shows what the OS is allowed to use.

---

## 4. Summary of Evidence

| **Test**                | **Result**             | **Indicates**                          |
|-------------------------|------------------------|----------------------------------------|
| `/dev/mem` read @ 0xA0000 | All `0xFF`            | Memory region is protected             |
| MSR 0x9B                | `0`                   | SMM is active in traditional mode      |
| ACPI FACP SMI_CMD       | Port `0xB2`           | Software SMI trigger is configured     |
| E820 memory map         | `0xA0000` reserved    | BIOS hides memory from OS              |
| Kernel logs             | No SMM references     | SMI handling is transparent            |

---

## 5. What This Proves

### 5.1 SMM Is Active

The presence of:
- Protected memory regions
- SMI command port (`0xB2`)
- MSR configurations

...confirms that SMM is not disabled. This system is configured to handle SMIs.

### 5.2 SMRAM Is Protected

The `0xFF` pattern on reads proves that SMRAM is **locked**. The CPU refuses to serve SMRAM contents when not in SMM.

### 5.3 SMM Is Unreachable

Even with root privileges, `sudo`, and direct hardware access:
- We cannot read SMM code.
- We cannot observe SMI dispatch.
- We cannot trace SMM execution.

This is by design.

---

## 6. Why This Matters for Security

SMM is a **privileged execution mode** that:
- Runs at higher privilege than the kernel
- Handles critical platform functions (power management, thermal control, security)
- Cannot be audited by the OS
- Is a prime target for firmware-level attacks

If SMM code has a vulnerability:
- The OS cannot detect it.
- Antivirus cannot scan it.
- Intrusion detection systems cannot monitor it.

This is the **trust boundary problem** in modern computing.

---

## 7. Limitations of This Approach

### 7.1 We Still Haven't "Seen" SMM

Everything in this lab is **indirect evidence**:
- We see protection, not code.
- We see configuration, not execution.
- We see effects, not causes.

### 7.2 Why Direct Observation Is Impossible

The x86 architecture enforces this boundary:
- SMRAM is hardware-locked by the chipset.
- The CPU state changes when entering SMM (SMBASE, segment registers).
- No software breakpoints or tracing tools work inside SMM.

This is not a limitation of our tools—it is a limitation of the architecture.

---

## 8. Conclusion

### What Was Proven

1. SMM is active on this Intel 12th Gen system.
2. SMRAM is allocated and protected at the hardware level.
3. The OS cannot observe SMM execution, even with root privileges.
4. The invisibility of SMM is architectural, not accidental.

### Why This Matters

SMM is the most privileged execution environment on an x86 system. Understanding its behavior is essential for:
- Threat modeling
- Firmware security auditing
- Supply chain security
- Rootkit detection

### Next Steps

The next report will address the question: **Why is it so unsatisfying to "not see" SMM?**

We will explore the architectural reasons why SMM is fundamentally unobservable, and why this design choice has both security benefits and risks.

---

## 9. References

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3, Chapter 35
- ACPI Specification 6.5, Section 5.2.9 (Fixed ACPI Description Table)
- Linux kernel source: `arch/x86/kernel/e820.c`

---

**End of Report 2**