from cvss import CVSS3, CVSS4
import os
import sys

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"

# CVSS v3.1 metrics
CVSS3_METRICS = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "I": ("Integrity", {"N": "None", "L": "Low", "H": "High"}),
    "A": ("Availability", {"N": "None", "L": "Low", "H": "High"}),
}

# CVSS v4.0 metrics
CVSS4_METRICS = {
    "AT": ("Attack Requirements", {"N": "None", "P": "Present"}),
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "P": "Passive", "A": "Active"}),
    "VC": ("Vulnerable System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "VI": ("Vulnerable System Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "VA": ("Vulnerable System Availability", {"H": "High", "L": "Low", "N": "None"}),
    "SC": ("Subsequent System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "SI": ("Subsequent System Integrity", {"H": "High", "S": "Safe", "N": "None"}),
    "SA": ("Subsequent System Availability", {"H": "High", "S": "Safe", "N": "None"}),
}

def get_severity(score, version):
    """Return severity label and color based on CVSS version and score."""
    if version == 3:
        # CVSS v3.1 severity ranges
        if score == 0.0:
            return "None", Colors.BLUE
        elif 0.1 <= score <= 3.9:
            return "Low", Colors.GREEN
        elif 4.0 <= score <= 6.9:
            return "Medium", Colors.YELLOW
        elif 7.0 <= score <= 8.9:
            return "High", Colors.MAGENTA
        else:  # 9.0 – 10.0
            return "Critical", Colors.RED
    else:
        # CVSS v4.0 severity ranges (as per NIST)
        if score == 0.0:
            return "None", Colors.BLUE
        elif 0.1 <= score <= 3.9:
            return "Low", Colors.GREEN
        elif 4.0 <= score <= 6.9:
            return "Medium", Colors.YELLOW
        elif 7.0 <= score <= 8.9:
            return "High", Colors.MAGENTA
        else:  # 9.0 – 10.0
            return "Critical", Colors.RED

def build_vector_interactively(version):
    os.system("clear" if os.name != "nt" else "cls")
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- Building CVSS v{version}.0 Vector Interactively ---{Colors.RESET}")
    metrics = CVSS3_METRICS if version == 3 else CVSS4_METRICS
    vector_parts = []

    for key, (desc, options) in metrics.items():
        print(f"\n{Colors.BOLD}{key}:{Colors.RESET} {desc}")
        for val, meaning in options.items():
            print(f"  {val} = {meaning}")
        while True:
            choice = input(f"Select value for {key}: ").strip().upper()
            if choice in options:
                vector_parts.append(f"{key}:{choice}")
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please pick one of: {', '.join(options.keys())}{Colors.RESET}")

    vector = "/".join(vector_parts)
    if version == 3:
        vector = "CVSS:3.1/" + vector
    else:
        vector = "CVSS:4.0/" + vector
    return vector

def calculate_cvss_score(vector, version):
    try:
        if version == 3:
            cvss_obj = CVSS3(vector)
        else:
            cvss_obj = CVSS4(vector)
        base_score = cvss_obj.scores()[0]
        return round(base_score, 1)  # Standard CVSS precision
    except Exception as e:
        print(f"{Colors.RED}Error parsing vector: {e}{Colors.RESET}")
        return None

def main():
    print(f"{Colors.BOLD}{Colors.CYAN}CVSS Base Score Calculator (v3.1 & v4.0){Colors.RESET}")
    print(f"by @cybereagle2001\n")

    # Choose version
    while True:
        ver_input = input("Choose CVSS version — enter 3 or 4: ").strip()
        if ver_input in ("3", "4"):
            version = int(ver_input)
            break
        print(f"{Colors.RED}Please enter '3' for CVSS v3.1 or '4' for CVSS v4.0.{Colors.RESET}")

    # Choose input method
    while True:
        method = input("\nHow would you like to input the vector?\n"
                       "[1] Paste full vector string\n"
                       "[2] Build vector interactively\n"
                       "Choose (1 or 2): ").strip()
        if method in ("1", "2"):
            break
        print(f"{Colors.RED}Please enter 1 or 2.{Colors.RESET}")

    if method == "1":
        vector = input("\nEnter your full CVSS vector: ").strip()
        if version == 3 and not vector.startswith("CVSS:3."):
            vector = "CVSS:3.1/" + vector
        elif version == 4 and not vector.startswith("CVSS:4.0/"):
            vector = "CVSS:4.0/" + vector
    else:
        vector = build_vector_interactively(version)

    print(f"\n{Colors.BOLD}→ Final vector:{Colors.RESET} {vector}")

    score = calculate_cvss_score(vector, version)
    if score is not None:
        severity, color = get_severity(score, version)
        print(f"\n{Colors.BOLD}Final CVSS v{version}.0 Base Score:{Colors.RESET} {color}{score}{Colors.RESET}")
        print(f"{Colors.BOLD}Severity Level:{Colors.RESET} {color}{severity}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}Failed to compute score.{Colors.RESET}")
        return None

    return float(score)

if __name__ == "__main__":
    final_score = main()
