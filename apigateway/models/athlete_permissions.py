import enum
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum
from db_connection import Base
from .users import Users
from sqlalchemy import types


class OperationsEnum(enum.Enum):
    view = 0
    edit = 1


class PermittedOperationEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        return OperationsEnum[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        return OperationsEnum(value).name    # Convert an integer to a name


class AthletePermissions(Base):
    __tablename__ = "athlete_permissions"

    athlete_id = Column(String, ForeignKey(Users.id), primary_key=True)
    user_id = Column(String, ForeignKey(Users.id), primary_key=True)
    permitted_operation = Column(PermittedOperationEnumType)
