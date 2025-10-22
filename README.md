# 🛡️ CVSS Wizard – Interactive CVSS Calculator (v3.1 & v4.0)


> **Build, validate, and score CVSS vectors like a pro — no more guesswork.**  
> Perfect for **pentesters**, **CTF players**, **vulnerability analysts**, and **security engineers**.

---

## 🔥 Why CVSS Wizard?

- ✅ **Supports both CVSS v3.1 and v4.0**  
- ✅ **Two input modes**: Paste a vector **or** build it step-by-step with guided questions  
- ✅ **Real-time validation** – no more malformed vectors  
- ✅ **Lightweight & offline** – powered by the official [`cvss`](https://pypi.org/project/cvss/) library  
- ✅ **Returns a clean numeric score** – ready for automation or reporting  

Whether you're racing through a CTF or writing a client report, **CVSS Wizard cuts through the noise** and gives you an accurate base score in seconds.

---

## 🚀 Quick Start

### 1. Install Dependencies
For Bash and zsh lovers :

```bash
pip install cvss
```

If you are stuck with windows and surviving with WSL: 

```wsl
sudo apt install python3-cvss
```


### 2. Run the Tool
```bash
python3 cvss_score_2.py
```
<img width="383" height="105" alt="image" src="https://github.com/user-attachments/assets/f05d4a41-72d2-46b9-a9c9-81b40fbd74c1" />

### 3. Follow the Prompts
- Choose CVSS version (`3` or `4`)
- Pick input method:
  - **[1]** Paste your vector (e.g., `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
  - **[2]** Answer interactive questions to build it from scratch
- Get your **final base score** instantly!

---

## 💡 Example Workflows

### 🎯 CTF Scenario – You find an RCE with no auth
```text
Choose CVSS version — enter 3 or 4: 3
How would you like to input the vector?
[1] Paste full vector string
[2] Build vector interactively
Choose (1 or 2): 2

--- Building CVSS v3.0 Vector Interactively ---
AV: Attack Vector
  N = Network
  A = Adjacent
  L = Local
  P = Physical
Select value for AV: N
AC: Attack Complexity
  L = Low
  H = High
Select value for AC: L
...
✅ Final vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
🎯 Final CVSS v3.0 Base Score: 9.8
```

### 🛠️ Pentest Report – You already have a vector from Burp
```text
Choose CVSS version — enter 3 or 4: 4
Choose (1 or 2): 1
Enter your full CVSS vector: AT:N/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
✅ Final vector: CVSS:4.0/AT:N/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
🎯 Final CVSS v4.0 Base Score: 9.3
```

---

## 🧠 Key Differences: CVSS v3.1 vs v4.0

| Aspect | CVSS v3.1 | CVSS v4.0 |
|-------|----------|----------|
| **Confidentiality** | `C:L/H/N` | Split into `VC` (Vulnerable) & `SC` (Subsequent) |
| **User Interaction** | `N` or `R` | `N`, `P` (Passive), or `A` (Active) |
| **Integrity/Availability** | Single impact | Separate metrics for vulnerable & subsequent systems |
| **New Metric** | — | `AT` (Attack Requirements) |
| **Use Case** | Legacy systems, most scanners | Modern risk modeling, cloud, chained exploits |

> 💡 **Pro Tip**: Use **v4.0** for complex attack chains or when assessing downstream impact!

---

## 📦 Requirements

- Python 3.7+
- [`cvss`](https://pypi.org/project/cvss/) library (`pip install cvss`)

> ⚠️ **No internet required!** All calculations happen locally using the official CVSS specification.

---

## 🛠️ Customize & Extend

Want more? Fork and add:
- 🔹 **Severity labels** (e.g., `Critical`, `High`)
- 🔹 **JSON/YAML output** for integration with ticketing systems
- 🔹 **Batch mode** for scoring multiple vectors
- 🔹 **Colorized output** with `rich` or `colorama`

---

## 📜 License

MIT License – free to use, modify, and distribute.  
*Use responsibly in authorized engagements only.*

---

## 🙌 Made For Security Pros, By Security Pros

> “Finally, a CVSS tool that doesn’t make me Google metric abbreviations mid-Mission.”  
> — *Every pentester ever*

---
✨ **Happy hacking, and may your CVSS scores always be critical!** ✨
