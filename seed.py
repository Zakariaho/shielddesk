"""Create the ShieldDesk database with SYNTHETIC data only.

Run:  python seed.py
Creates shielddesk.db and exports data/students.csv.
All names, IDs, e-mails and phone numbers are randomly generated and fake.
"""
import csv
import hashlib
import itertools
import os
import random
import sqlite3

import config

rng = random.Random(411)  # nosec B311 - synthetic data generator, not security-sensitive

FIRST = ["Amira", "Omar", "Layla", "Yusuf", "Noor", "Khalid", "Hana", "Tariq", "Sara", "Zayed",
         "Maya", "Rashid", "Dana", "Faisal", "Lina", "Hamdan", "Reem", "Adel", "Salma", "Karim"]
LAST = ["Al Mansoori", "Haddad", "Nasser", "Rahman", "Khan", "Farouk", "Saleh", "Qasim", "Darwish",
        "Iqbal", "Barakat", "Mahmoud", "Siddiqui", "Aziz", "Hamdi", "Jaber", "Rashed", "Tahir",
        "Zahra", "Sultan"]
PROGRAMS = ["Computer Science", "Cybersecurity", "Software Engineering",
            "Electrical Engineering", "Business Analytics"]
CATEGORIES = ["IT Support", "Transcript Request", "Course Registration",
              "Fee Query", "Library Access", "Room Booking"]
DESCRIPTIONS = [
    "I cannot log in to the student portal.",
    "Please issue an official transcript for my visa application.",
    "I need to add a course after the registration deadline.",
    "My tuition invoice shows an incorrect amount.",
    "I lost access to the library e-resources.",
    "Requesting a study room for a group project.",
    "The campus Wi-Fi keeps disconnecting in Building B.",
    "Please update my phone number on record.",
]
FAQ = [
    ("How do I reset my password?", "Use the reset link on the portal or visit the IT desk."),
    ("How do I request a transcript?", "Submit a Transcript Request through ShieldDesk."),
    ("When is the registration deadline?", "Registration closes at the end of week two."),
    ("How do I pay my fees?", "Fees can be paid online or at the finance office."),
    ("How do I book a study room?", "Submit a Room Booking request at least 24 hours ahead."),
    ("Where is the IT help desk?", "Building A, ground floor, 8am to 4pm."),
    ("How do I connect to campus Wi-Fi?", "Select the campus network and sign in with your portal login."),
    ("How do I access library e-resources?", "Log in through the library page with your student account."),
]


def md5(password):
    return hashlib.md5(password.encode()).hexdigest()  # nosec B324 - mirrors the app's v0 hashing so seeded logins work


def main():
    if os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)
    os.makedirs("data", exist_ok=True)
    db = sqlite3.connect(config.DB_PATH)
    db.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL,
            student_id TEXT,
            email TEXT,
            phone TEXT,
            date_of_birth TEXT,
            program TEXT
        );
        CREATE TABLE requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            student_id TEXT,
            category TEXT,
            description TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT
        );
        CREATE TABLE faq (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            answer TEXT
        );
    """)

    names = rng.sample(list(itertools.product(FIRST, LAST)), 56)
    ids = rng.sample(range(1000, 9999), 50)

    # 1 admin, 5 staff, 50 students
    db.execute("INSERT INTO users (username,password_hash,role,full_name,email) VALUES (?,?,?,?,?)",
               ("admin", md5("Admin@123"), "admin", "System Administrator", "admin@shielddesk.test"))
    for i in range(1, 6):
        first, last = names[i - 1]
        db.execute("INSERT INTO users (username,password_hash,role,full_name,email) VALUES (?,?,?,?,?)",
                   (f"staff{i}", md5("Staff@123"), "staff", f"{first} {last}", f"staff{i}@shielddesk.test"))

    students = []
    for i in range(1, 51):
        first, last = names[5 + i]
        username = f"student{i:02d}"
        student_id = f"2024{ids[i - 1]}"
        email = f"{username}@student.shielddesk.test"
        phone = f"+971-50-555-{rng.randint(0, 9999):04d}"
        dob = f"{rng.randint(2000, 2006)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
        program = rng.choice(PROGRAMS)
        db.execute("""INSERT INTO users
            (username,password_hash,role,full_name,student_id,email,phone,date_of_birth,program)
            VALUES (?,?,?,?,?,?,?,?,?)""",
                   (username, md5("Student@123"), "student", f"{first} {last}",
                    student_id, email, phone, dob, program))
        students.append([f"{first} {last}", student_id, email, phone, dob, program])

    # 120 requests spread across the students (user ids 7..56)
    for _ in range(120):
        user_id = rng.randint(7, 56)
        sid = students[user_id - 7][1]
        db.execute("INSERT INTO requests (user_id,student_id,category,description,status,created_at) VALUES (?,?,?,?,?,?)",
                   (user_id, sid, rng.choice(CATEGORIES), rng.choice(DESCRIPTIONS),
                    rng.choice(["Open", "In Progress", "Closed"]),
                    f"2026-10-{rng.randint(1, 28):02d}"))

    db.executemany("INSERT INTO faq (title, answer) VALUES (?,?)", FAQ)
    db.commit()
    db.close()

    with open("data/students.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["full_name", "student_id", "email", "phone", "date_of_birth", "program"])
        w.writerows(students)

    print("Created", config.DB_PATH, "- 1 admin, 5 staff, 50 students, 120 requests, 8 FAQ entries")
    print("Exported data/students.csv")


if __name__ == "__main__":
    main()
