import logging
from backend.database import SessionLocal
from backend.models import Organization, User, Project, ScanTarget

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def seed_db():
    db = SessionLocal()
    try:
        # Check if already seeded
        existing_org = db.query(Organization).first()
        if existing_org:
            logger.info("Database already seeded.")
            return

        logger.info("Starting database seeding...")
        
        # 1. Create Organization
        org = Organization(name="Seed Corp")
        db.add(org)
        db.commit()
        db.refresh(org)
        logger.info(f"Created Org: {org.name} ({org.id})")

        # 2. Create Admin User
        user = User(
            email="admin@seedcorp.com",
            firebase_uid="seed_admin_uid",
            role="org_admin",
            is_active=True,
            organization_id=org.id
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Created User: {user.email} with role {user.role} ({user.id})")

        # 3. Create Project
        project = Project(
            name="Default Project",
            organization_id=org.id
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        logger.info(f"Created Project: {project.name} ({project.id})")

        # 4. Create Scan Target
        target = ScanTarget(
            url="https://example.com",
            project_id=project.id
        )
        db.add(target)
        db.commit()
        db.refresh(target)
        logger.info(f"Created Target: {target.url} ({target.id})")

        logger.info("Database seeding completed successfully.")

    except Exception as e:
        db.rollback()
        logger.error(f"Seeding failed: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_db()
