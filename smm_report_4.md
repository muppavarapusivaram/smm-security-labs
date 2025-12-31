# Lab 3: Understanding SMM by Reading Real Firmware Source Code

**Research Series: SMM/SMRAM Security Analysis**  
**Author:** MUPPAVARAPU SIVARAM  
**Institution:** KL University Vijayawada  
**ID:** 2300030447  
**Date:** December 2024  

---

## 1. Introduction

Previous reports established that SMM is architecturally invisible to the operating system. We proved SMM exists, but we could not see its code or observe its execution.

This report takes a different approach: **static source code analysis** of real SMM firmware.

We will analyze the **EDK II** (EFI Development Kit II) project, which is the open-source reference implementation of UEFI firmware. EDK II includes production-quality SMM drivers used by major hardware vendors.

**This is not reverse engineering.** This is reading publicly available, vendor-maintained source code.

---

## 2. What Is EDK II?

### 2.1 Project Overview

- **Repository:** https://github.com/tianocore/edk2
- **Maintained by:** TianoCore (Intel-led open-source community)
- **Used by:** Intel, AMD, ARM, and major OEMs
- **Language:** C and Assembly (x86, x64, ARM, AARCH64)
- **License:** BSD 2-Clause

### 2.2 Why EDK II Matters

Most x86 systems use firmware based on EDK II. This includes:
- Intel NUCs
- Surface devices
- Server platforms (Dell, HP, Lenovo)
- Custom embedded systems

**Reading EDK II code is reading real production firmware.**

---

## 3. SMM Components in EDK II

### 3.1 Directory Structure

The SMM-related code is located in:

```
edk2/
├── MdeModulePkg/
│   └── Core/
│       └── PiSmmCore/          # SMM Core (dispatcher, services)
├── UefiCpuPkg/
│   └── PiSmmCpuDxeSmm/         # CPU-specific SMM setup
└── MdePkg/
    └── Include/
        └── Protocol/           # SMM protocol definitions
```

**Key Components:**
- **PiSmmCore:** The SMM kernel (analogous to Linux kernel core)
- **PiSmmCpuDxeSmm:** Low-level CPU initialization and SMI entry/exit
- **SMM Drivers:** Individual handlers for power, thermal, etc.

---

## 4. What Does "DXE_SMM_DRIVER" Mean?

### 4.1 The Module Type

In EDK II, firmware drivers are classified by **module type**. Common types include:

| **Module Type**       | **Execution Context**              |
|-----------------------|------------------------------------|
| `SEC`                 | Security phase (earliest boot)     |
| `PEI_CORE`            | Pre-EFI Initialization             |
| `DXE_DRIVER`          | Driver Execution Environment       |
| `DXE_SMM_DRIVER`      | SMM Driver (runs in SMRAM)         |
| `DXE_RUNTIME_DRIVER`  | Runs during OS runtime             |

**`DXE_SMM_DRIVER`** means:
- The driver is loaded into SMRAM during boot.
- It registers SMI handlers.
- It executes only when SMIs occur.

### 4.2 Example: A Real SMM Driver INF File

```ini
[Defines]
  INF_VERSION                    = 0x00010005
  BASE_NAME                      = PiSmmCpuDxeSmm
  MODULE_TYPE                    = DXE_SMM_DRIVER
  ENTRY_POINT                    = PiCpuSmmEntry

[Sources]
  PiSmmCpuDxeSmm.c
  SmmCpuMemoryManagement.c
  Ia32/SmmInit.nasm
  X64/SmmInit.nasm

[LibraryClasses]
  SmmServicesTableLib
  BaseMemoryLib
  DebugLib
```

**Key Fields:**
- **MODULE_TYPE:** `DXE_SMM_DRIVER` — This is an SMM driver.
- **ENTRY_POINT:** `PiCpuSmmEntry` — Function called when the driver loads.
- **Sources:** Includes both C and assembly (`.nasm`) files.

---

## 5. PiSmmCore: The SMM Kernel

### 5.1 What PiSmmCore Does

**File:** `MdeModulePkg/Core/PiSmmCore/PiSmmCore.c`

**Responsibilities:**
1. Initializes SMRAM allocation
2. Loads SMM drivers into SMRAM
3. Registers SMI handlers
4. Dispatches SMIs to the correct handler

**This is the SMM equivalent of the Linux kernel's init process.**

### 5.2 Key Data Structure: `SMM_CORE_PRIVATE_DATA`

```c
typedef struct {
  UINTN                     Signature;
  EFI_HANDLE                SmmIplImageHandle;
  SMM_CORE_SMI_HANDLERS     SmiHandlerList;
  EFI_SMM_SYSTEM_TABLE2     *Smst;
  VOID                      *SmmEntryPoint;
  BOOLEAN                   SmmEntryPointRegistered;
  BOOLEAN                   InSmm;
} SMM_CORE_PRIVATE_DATA;
```

**Important Fields:**
- **`SmiHandlerList`**: Linked list of registered SMI handlers.
- **`Smst`**: Pointer to the SMM System Table (like UEFI System Table, but for SMM).
- **`InSmm`**: Boolean flag indicating if CPU is currently in SMM.

---

## 6. SMI Entry: From Hardware Interrupt to Handler

### 6.1 The SMI Entry Flow

When a hardware SMI occurs:

```
1. CPU receives SMI signal
   ↓
2. CPU saves state to SMRAM (automatic, hardware-controlled)
   ↓
3. CPU jumps to SMBASE + 0x8000 (SMM entry point)
   ↓
4. Assembly stub (SmmInit.nasm) executes
   ↓
5. C code (SmiEntry) is called
   ↓
6. PiSmmCore dispatches to registered handler
   ↓
7. Handler executes
   ↓
8. RSM instruction executed
   ↓
9. CPU restores state and returns to OS
```

### 6.2 The Assembly Entry Stub

**File:** `UefiCpuPkg/PiSmmCpuDxeSmm/X64/SmmInit.nasm`

```nasm
global ASM_PFX(SmmInit)
ASM_PFX(SmmInit):
    ; Save CPU state
    push    rax
    push    rcx
    push    rdx
    
    ; Switch to SMM stack
    mov     rsp, qword [ASM_PFX(gSmmInitStack)]
    
    ; Call C handler
    call    ASM_PFX(SmiHandler)
    
    ; Restore state
    pop     rdx
    pop     rcx
    pop     rax
    
    ; Exit SMM
    rsm
```

**Key Instructions:**
- **`push` / `pop`:** Save and restore registers.
- **`mov rsp, ...`:** Switch to a dedicated SMM stack (isolated from OS stack).
- **`call SmiHandler`:** Jump to C code.
- **`rsm`:** Resume from SMM (return to OS).

**This is the lowest-level SMM code that executes.**

---

## 7. CPU State Save Area

### 7.1 What Is the State Save Area?

When the CPU enters SMM, it saves the current execution context to a region in SMRAM called the **state save area**.

**Saved State Includes:**
- General-purpose registers (`RAX`, `RBX`, `RCX`, ...)
- Instruction pointer (`RIP`)
- Stack pointer (`RSP`)
- Flags (`RFLAGS`)
- Segment registers (`CS`, `DS`, ...)
- Control registers (`CR0`, `CR3`, ...)

**Purpose:**
- Allows SMM to execute without corrupting OS state.
- Allows RSM instruction to restore the OS exactly as it was.

### 7.2 State Save Map in EDK II

**File:** `UefiCpuPkg/PiSmmCpuDxeSmm/SmramSaveState.c`

```c
typedef struct {
  UINT64  Reserved1[2];  
  UINT64  R15;
  UINT64  R14;
  UINT64  R13;
  UINT64  R12;
  UINT64  R11;
  UINT64  R10;
  UINT64  R9;
  UINT64  R8;
  UINT64  Rax;
  UINT64  Rcx;
  UINT64  Rdx;
  UINT64  Rbx;
  UINT64  Rsp;
  UINT64  Rbp;
  UINT64  Rsi;
  UINT64  Rdi;
  // ... more fields
} SMM_SAVE_STATE_MAP;
```

**This structure maps to the hardware-defined layout in SMRAM.**

---

## 8. SMBASE Relocation

### 8.1 What Is SMBASE?

**SMBASE** is a CPU register (not exposed as an MSR) that determines where SMRAM begins for each CPU.

**Default SMBASE:** `0x30000` (legacy address)

**Problem:**
- Modern systems need more control over SMRAM location.
- Multi-core systems need per-CPU SMRAM regions.

**Solution:** Relocate SMBASE during boot.

### 8.2 SMBASE Relocation Code

**File:** `UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.c`

```c
VOID
SmmRelocateBases (
  VOID
  )
{
  UINTN   Index;
  UINT32  NewSmbase;
  
  for (Index = 0; Index < gSmmCpuPrivate->NumberOfCpus; Index++) {
    // Calculate new SMBASE for this CPU
    NewSmbase = (UINT32)(gSmmCpuPrivate->SmramBase + Index * SIZE_32KB);
    
    // Write new SMBASE to CPU's state save area
    *(UINT32 *)(UINTN)(gSmmCpuPrivate->SmmBase[Index] + 0xFF00) = NewSmbase;
    
    // Trigger SMI to apply new SMBASE
    SendSmiIpi (Index);
  }
}
```

**What Happens:**
1. Firmware calculates a new SMBASE for each CPU.
2. Firmware writes the new SMBASE to the state save area.
3. Firmware triggers an SMI.
4. When the CPU exits SMM (via RSM), it reads the new SMBASE and uses it for future SMIs.

**This is a one-time operation during boot.**

---

## 9. SMRAM Allocation and Locking

### 9.1 How SMRAM Is Allocated

**File:** `MdeModulePkg/Core/PiSmmCore/PiSmmCore.c`

```c
EFI_STATUS
SmmAllocatePages (
  IN  EFI_ALLOCATE_TYPE         Type,
  IN  EFI_MEMORY_TYPE           MemoryType,
  IN  UINTN                     NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS      *Memory
  )
{
  // Allocate memory from SMRAM pool
  *Memory = InternalAllocMaxAddress (
              gSmmCorePrivate->SmramBase,
              gSmmCorePrivate->SmramSize,
              NumberOfPages
            );
  
  return EFI_SUCCESS;
}
```

**Key Points:**
- SMRAM is a contiguous memory pool.
- SMM drivers allocate from this pool (like `malloc` in userspace).
- Once allocated, memory is never freed (no `free` in SMM).

### 9.2 SMRAM Locking

**File:** `UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.c`

```c
VOID
LockSmram (
  VOID
  )
{
  UINT8  SmramControl;
  
  // Read current SMRAM control register
  SmramControl = PciRead8 (PCI_LIB_ADDRESS (0, 0, 0, SMRAM_OFFSET));
  
  // Set the D_LCK (lock) bit
  SmramControl |= D_LCK;
  
  // Write back to chipset
  PciWrite8 (PCI_LIB_ADDRESS (0, 0, 0, SMRAM_OFFSET), SmramControl);
}
```

**What This Does:**
- Reads the **SMRAMC** register from the chipset (via PCI config space).
- Sets the **D_LCK** bit (lock bit).
- Once locked, SMRAM cannot be unlocked without a system reset.

**This is the point of no return for SMRAM protection.**

---

## 10. SMI Dispatcher Architecture

### 10.1 What Is the SMI Dispatcher?

When an SMI occurs, the CPU does not know **what caused it**. The **SMI dispatcher** determines which handler should execute.

**Dispatcher Flow:**

```
SMI occurs
  ↓
Dispatcher reads SMI status registers
  ↓
Dispatcher determines SMI source (e.g., software SMI, I/O trap, power button)
  ↓
Dispatcher looks up registered handler for that source
  ↓
Dispatcher calls the handler
```

### 10.2 Registering an SMI Handler

**File:** `MdeModulePkg/Core/PiSmmCore/Smi.c`

```c
EFI_STATUS
SmiHandlerRegister (
  IN  EFI_SMM_HANDLER_ENTRY_POINT2  Handler,
  IN  CONST EFI_GUID                *HandlerType  OPTIONAL,
  OUT EFI_HANDLE                    *DispatchHandle
  )
{
  SMI_HANDLER  *SmiHandler;
  
  // Allocate handler structure
  SmiHandler = AllocatePool (sizeof (SMI_HANDLER));
  
  // Store handler function pointer
  SmiHandler->Handler = Handler;
  SmiHandler->HandlerType = HandlerType;
  
  // Add to global list
  InsertTailList (&gSmmCorePrivate->SmiHandlerList, &SmiHandler->Link);
  
  return EFI_SUCCESS;
}
```

**What This Does:**
- SMM drivers call `SmiHandlerRegister` during initialization.
- The dispatcher maintains a linked list of handlers.
- When an SMI occurs, the dispatcher walks this list and calls matching handlers.

---

## 11. Software SMI Handlers

### 11.1 What Is a Software SMI?

A **software SMI** is triggered by writing a byte to the SMI command port (typically port `0xB2`).

**Example:**
```c
// Trigger software SMI with command code 0x42
OutByte (0xB2, 0x42);
```

The byte written (e.g., `0x42`) is called the **SMI command code**.

### 11.2 Software SMI Handler Registration

**File:** `MdeModulePkg/Universal/SmmCommunicationBufferDxe/SmmCommunicationBufferDxe.c`

```c
EFI_STATUS
RegisterSwSmiHandler (
  IN  UINT8                     SwSmiNumber,
  IN  EFI_SMM_HANDLER_ENTRY_POINT2  Handler
  )
{
  EFI_SMM_SW_REGISTER_CONTEXT  SwContext;
  
  SwContext.SwSmiInputValue = SwSmiNumber;
  
  return gSwDispatch->Register (
           gSwDispatch,
           Handler,
           &SwContext,
           &DispatchHandle
         );
}
```

**What This Does:**
- Registers a handler for a specific software SMI command code.
- When `0x42` is written to port `0xB2`, the corresponding handler is called.

---

## 12. Communication Buffers: OS-to-SMM Interface

### 12.1 The Problem

The OS needs to pass data to SMM (e.g., "please enable this power state"). But:
- The OS cannot write to SMRAM.
- SMM cannot read OS memory safely (could be malicious).

**Solution:** Use a **communication buffer** in shared memory.

### 12.2 How Communication Buffers Work

```
1. OS allocates buffer in normal RAM
   ↓
2. OS writes data to buffer
   ↓
3. OS triggers software SMI
   ↓
4. SMM reads buffer (validates data)
   ↓
5. SMM processes request
   ↓
6. SMM writes result to buffer
   ↓
7. SMM returns (RSM)
   ↓
8. OS reads result from buffer
```

### 12.3 The Security Risk

**File:** `MdeModulePkg/Core/PiSmmCore/MemoryAttributesTable.c`

```c
EFI_STATUS
ValidateCommunicationBuffer (
  IN  VOID   *Buffer,
  IN  UINTN  Length
  )
{
  // Check if buffer is outside SMRAM
  if (IsBufferInSmram (Buffer, Length)) {
    return EFI_SECURITY_VIOLATION;
  }
  
  // Check if buffer overlaps MMIO
  if (IsBufferInMmio (Buffer, Length)) {
    return EFI_SECURITY_VIOLATION;
  }
  
  return EFI_SUCCESS;
}
```

**Why This Is Critical:**
- If SMM does not validate the buffer pointer, the OS can trick SMM into reading/writing SMRAM.
- This is the most common class of SMM vulnerabilities (**SMM callout vulnerabilities**).

**Historical CVEs:**
- **CVE-2017-5703:** Intel AMT SMM vulnerability (buffer validation bypass)
- **CVE-2018-3658:** Dell BIOS SMM vulnerability (buffer pointer not checked)

---

## 13. Why Bugs Here Are Catastrophic

### 13.1 Privilege Elevation

If an attacker finds a bug in an SMM handler:
- They can execute code in SMM (Ring -2).
- They can read/write SMRAM.
- They can persist malware in firmware.
- They can bypass Secure Boot, TPM, and all OS-level security.

**This is higher privilege than a kernel exploit.**

### 13.2 Real-World Impact

**Example Attack (Simplified):**
1. Attacker triggers software SMI with malicious buffer pointer.
2. SMM handler does not validate pointer.
3. SMM reads attacker-controlled data as if it were legitimate.
4. Attacker overwrites SMRAM with shellcode.
5. SMM executes attacker's code.

**Outcome:**
- Attacker has full control of the system.
- Malware survives OS reinstalls.
- Malware is invisible to antivirus.

### 13.3 Why SMM Bugs Are Hard to Fix

- Firmware updates are rare.
- Users often don't apply firmware updates.
- Some systems never receive updates.
- Firmware updates can brick devices if done incorrectly.

**An SMM vulnerability can remain exploitable for years.**

---

## 14. Conclusion

### What Was Learned

By reading EDK II source code, we learned:

1. **What `DXE_SMM_DRIVER` means:** A driver that runs in SMRAM.
2. **How PiSmmCore works:** The SMM kernel that dispatches SMIs.
3. **How SMI entry works:** Assembly stubs, state save areas, and C handlers.
4. **How SMBASE relocation works:** Per-CPU SMRAM allocation during boot.
5. **How SMRAM is locked:** The `D_LCK` bit in the SMRAMC register.
6. **How the SMI dispatcher works:** A linked list of registered handlers.
7. **How software SMI handlers work:** Triggered by writing to port `0xB2`.
8. **How communication buffers work:** Shared memory for OS-to-SMM communication.
9. **Why bugs are catastrophic:** SMM is the highest privilege level on x86.

### What SMM Actually Is (In Code)

- SMM is a **kernel that runs alongside the OS**.
- It has its own memory allocator, dispatcher, and driver model.
- It is written in C and assembly, just like any OS kernel.
- It is **architecturally invisible** but **logically understandable**.

### Why This Matters for Security

SMM is:
- **Necessary:** Modern platforms require SMM for power management, security features, and hardware control.
- **Dangerous:** SMM bugs grant attackers firmware-level persistence and control.
- **Difficult to secure:** SMM code is hard to audit, hard to update, and hard to test.

**Firmware security is the weakest link in modern platform security.**

### Next Steps

The final report will consolidate everything learned across all four labs and discuss the broader security implications of SMM.

---

## 15. References

- EDK II Project: https://github.com/tianocore/edk2
- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3, Chapter 35
- UEFI Specification 2.10, Section II-13 (SMM Services)
- *Getting into the SMRAM: SMM Reloaded* — Invisible Things Lab, CanSecWest 2009
- *Attacking Intel BIOS* — Invisible Things Lab, Black Hat 2009

---

**End of Report 4**