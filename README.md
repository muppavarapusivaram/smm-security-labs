# System Management Mode (SMM) Research Journal

**Author:** MUPPAVARAPU SIVARAM
**Platform:** Arch Linux on Intel hardware

---

## Overview

This repository documents a structured, hands-on research journey into **Intel System Management Mode (SMM)** and **SMRAM**, one of the most privileged and least visible execution environments in modern x86 systems.

The goal of this work is **understanding, not exploitation**. The focus is on architectural behavior, OS–firmware trust boundaries, and security implications of code that runs below the operating system and hypervisor.

All experiments are performed on **real hardware**, avoiding emulation shortcuts, to ensure observations reflect actual platform behavior.

---

## What This Repository Covers

This project is organized as a series of labs and reports, each building on the previous one:

* **Lab 1 – OS Visibility Limits**
  Demonstrates what a modern Linux OS can and cannot see regarding firmware memory and execution.

* **Lab 2 – Existence of SMM & SMRAM**
  Proves that SMM is active and protected on real hardware, even though it is invisible to the OS.

* **Lab 2 (Extended) – Why SMM Cannot Be “Seen”**
  Explains why traditional debugging and memory inspection tools fundamentally fail against SMM.

* **Lab 3 – Static Analysis of Real SMM Firmware Code**
  Deep analysis of EDK II SMM source code to understand how SMM is implemented, entered, dispatched, and locked.

* **Final Report – Security Implications**
  Consolidates learning into a clear mental model of SMM, its risks, and why firmware security matters.

---

## Key Themes

* Firmware executes **below the OS and hypervisor**
* SMRAM is **hardware-isolated and locked**
* SMM is **trigger-based**, not continuously running
* OS–SMM communication is **hostile by design**
* Bugs in SMM have **system-wide, persistent impact**

---

## What This Is *Not*

* Not an exploitation guide
* Not a rootkit tutorial
* Not bypassing Secure Boot or Boot Guard
* Not reverse-engineering proprietary firmware binaries

This is an **educational and defensive security study**.

---

## Why This Matters

Modern system security does not stop at the kernel.

SMM has access to all system memory, executes invisibly, and persists across OS reinstalls. Understanding how it works is essential for:

* Firmware security research
* Platform trust analysis
* Hardware-backed security design
* Advanced kernel and low-level systems engineering

---

## Status

This repository represents an **ongoing research log**. Content may expand as deeper firmware components and historical vulnerabilities are studied.

---

*Maintained by MUPPAVARAPU SIVARAM*
