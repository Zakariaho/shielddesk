"""
pseudonymise.py - Task 4, Deliverable 5
Applies pseudonymisation to data/students.csv.
Replaces directly identifying fields with pseudonyms/generalised values.
Synthetic data only - no real PII processed.
"""
import csv
import hashlib
import os

INPUT  = "data/students.csv"
OUTPUT = "data/students_pseudonymised.csv"
SALT   = "shielddesk-pseudo-salt-2026"


def pseudonymise_name(name):
    h = hashlib.sha256((SALT + name).encode()).hexdigest()[:10].upper()
    return f"UID-{h}"


def generalise_phone(phone):
    return "+971-50-XXX-XXXX" if phone.startswith("+971") else "XXX-XXX-XXXX"


def generalise_dob(dob):
    return dob[:4] + "-XX-XX"


def main():
    os.makedirs("data", exist_ok=True)
    with open(INPUT) as fin, open(OUTPUT, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        orig = list(reader)
        pseudo = []
        for row in orig:
            p = {
                "full_name"    : pseudonymise_name(row["full_name"]),
                "student_id"   : row["student_id"],
                "email"        : "REDACTED",
                "phone"        : generalise_phone(row["phone"]),
                "date_of_birth": generalise_dob(row["date_of_birth"]),
                "program"      : row["program"],
            }
            pseudo.append(p)
            writer.writerow(p)

    print("=== BEFORE (3 rows) ===")
    for r in orig[:3]:
        print(dict(r))
    print("\n=== AFTER pseudonymisation (3 rows) ===")
    for r in pseudo[:3]:
        print(dict(r))
    print("\nDone. Output saved to", OUTPUT)


if __name__ == "__main__":
    main()
