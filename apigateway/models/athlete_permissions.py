from enum import Enum
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum, text
from sqlalchemy.dialects.postgresql.base import UUID
from sqlalchemy import types
from db_connection import Base


class PermittedOperationsEnum(Enum):
    forbidden = 0
    read_athlete_data = 1
    write_athlete_data = 2


class PermittedOperationsEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        return PermittedOperationsEnum[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        return PermittedOperationsEnum(value).name    # Convert an integer to a name


class AthletePermission(Base):
    __tablename__ = 'athlete_permissions'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    athlete_id = Column(UUID, index=True)
    user_id = Column(UUID, index=True)
    permitted_operation = Column(PermittedOperationsEnumType)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
