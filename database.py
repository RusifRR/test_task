from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


engine = create_engine('sqlite:///models.db', echo=False)

class Base(DeclarativeBase):
    pass


SessionLocal = sessionmaker(bind=engine, autocommit=False)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_session():
    with SessionLocal() as s:
        yield s
        
        