import hashlib
import random
from datetime import datetime, timedelta, timezone

from faker import Faker

from bank.app.db import connect, initialize_schema


def seed_database() -> None:
    fake = Faker()
    random.seed(42)
    with connect() as connection:
        initialize_schema(connection)
        if connection.execute("SELECT 1 FROM customers LIMIT 1").fetchone():
            return

        customers = []
        for customer_id in range(1, 51):
            email = f"customer{customer_id}@example.test"
            password_hash = hashlib.md5(b"password123").hexdigest()
            customers.append((customer_id, fake.name(), email, password_hash))
        connection.executemany(
            "INSERT INTO customers(id, name, email, password_hash) VALUES (?, ?, ?, ?)",
            customers,
        )

        accounts = []
        for account_id in range(1, 121):
            customer_id = ((account_id - 1) % 50) + 1
            accounts.append(
                (account_id, customer_id, f"ACCT-{account_id:08d}", round(random.uniform(100, 10000), 2))
            )
        connection.executemany(
            "INSERT INTO accounts(id, customer_id, account_number, balance) VALUES (?, ?, ?, ?)",
            accounts,
        )

        start = datetime.now(timezone.utc) - timedelta(days=365)
        transactions = []
        for transaction_id in range(1, 2001):
            account_id = ((transaction_id - 1) % 120) + 1
            amount = round(random.uniform(2, 500), 2)
            kind = random.choice(("credit", "debit"))
            transactions.append(
                (
                    transaction_id,
                    account_id,
                    kind,
                    amount,
                    fake.sentence(nb_words=4),
                    "",
                    (start + timedelta(minutes=transaction_id)).isoformat(),
                )
            )
        connection.executemany(
            """
            INSERT INTO transactions
                (id, account_id, kind, amount, description, memo, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            transactions,
        )

        staff = [
            (1, "Asha Admin", "admin@example.test", "admin"),
            (2, "Ravi Support", "support@example.test", "support"),
            (3, "Mina Auditor", "auditor@example.test", "auditor"),
        ]
        connection.executemany(
            "INSERT INTO staff(id, name, email, role) VALUES (?, ?, ?, ?)", staff
        )
        connection.commit()


if __name__ == "__main__":
    seed_database()
