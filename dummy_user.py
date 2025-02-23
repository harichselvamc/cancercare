# create_dummy_users.py

from main import SessionLocal, User, get_password_hash, Base, engine
from sqlalchemy.exc import IntegrityError

def create_dummy_users():
    # Ensure all tables are created
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        dummy_users = [
            {
                "name": "John Doe",
                "email": "john.doe@example.com",
                "password": "password",
                "age": 30,
                "phone": "1234567890",
                "guardian_phone": "0987654321",
                "role": "patient"
            },
            {
                "name": "Jane Smith",
                "email": "jane.smith@example.com",
                "password": "password",
                "age": 28,
                "phone": "1112223333",
                "guardian_phone": None,
                "role": "caregiver"
            },
            {
                "name": "Dr. Strange",
                "email": "dr.strange@example.com",
                "password": "password",
                "age": 45,
                "phone": "4445556666",
                "guardian_phone": None,
                "role": "doctor"
            },
        ]

        for user_data in dummy_users:
            # Check if the user already exists by email
            existing_user = db.query(User).filter(User.email == user_data["email"]).first()
            if not existing_user:
                hashed_password = get_password_hash(user_data["password"])
                new_user = User(
                    name=user_data["name"],
                    email=user_data["email"],
                    hashed_password=hashed_password,
                    age=user_data["age"],
                    phone=user_data["phone"],
                    guardian_phone=user_data["guardian_phone"],
                    role=user_data["role"]
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                print(f"Created user: {new_user.name} with role {new_user.role}")
            else:
                print(f"User already exists: {existing_user.name}")
    except Exception as e:
        db.rollback()
        print("Error creating dummy users:", e)
    finally:
        db.close()

if __name__ == "__main__":
    create_dummy_users()
