from cvss import CVSS3, CVSS4
import os

# CVSS v3.1 metrics with short descriptions and valid values
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

def build_vector_interactively(version):
    os.system("clear")
    print(f"\n--- Building CVSS v{version}.0 Vector Interactively ---")
    metrics = CVSS3_METRICS if version == 3 else CVSS4_METRICS
    vector_parts = []

    for key, (desc, options) in metrics.items():
        print(f"\n{key}: {desc}")
        for val, meaning in options.items():
            print(f"  {val} = {meaning}")
        while True:
            choice = input(f"Select value for {key}: ").strip().upper()
            if choice in options:
                vector_parts.append(f"{key}:{choice}")
                break
            else:
                print(f"Invalid choice. Please pick one of: {', '.join(options.keys())}")

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
        return base_score
    except Exception as e:
        print(f"Error parsing vector: {e}")
        return None

def main():
    print("CVSS Base Score Calculator (v3.1 & v4.0) \n by @cybereagle2001")
    
    # Choose version
    while True:
        ver_input = input("\nChoose CVSS version — enter 3 or 4: ").strip()
        if ver_input in ("3", "4"):
            version = int(ver_input)
            break
        print("Please enter '3' for CVSS v3.1 or '4' for CVSS v4.0.")

    # Choose input method
    while True:
        method = input("\nHow would you like to input the vector?\n"
                       "[1] Paste full vector string\n"
                       "[2] Build vector interactively\n"
                       "Choose (1 or 2): ").strip()
        if method in ("1", "2"):
            break
        print(" Please enter 1 or 2.")

    if method == "1":
        vector = input("\nEnter your full CVSS vector: ").strip()
        # Auto-prepend prefix if missing
        if version == 3 and not vector.startswith("CVSS:3."):
            vector = "CVSS:3.1/" + vector
        elif version == 4 and not vector.startswith("CVSS:4.0/"):
            vector = "CVSS:4.0/" + vector
    else:
        vector = build_vector_interactively(version)

    print(f"\n-> Final vector: {vector}")

    score = calculate_cvss_score(vector, version)
    if score is not None:
        print(f"\n Final CVSS v{version}.0 Base Score: {score}")
    else:
        print("\n Failed to compute score.")
        return None

    return float(score)

if __name__ == "__main__":
    final_score = main()
    
