import enum
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum, text, ARRAY
from db_connection import Base
from models._types import EnumTypeBase


class InjuryStatusEnumtype(EnumTypeBase):
    name_values = {
                'healthy': 0,
                'healthy_chronically_injured': 1,
                'injured': 2
            }


class AccountEnumType(EnumTypeBase):
    name_values = { 'paid': 0,
                    'free': 1
                  }


class AccountStatusEnumType(EnumTypeBase):
    name_values = {
                  'active': 0,
                  'pending': 1,
                  'past_due': 2,
                  'expired': 3
                  }


class SystemTypeEnumType(EnumTypeBase):
    name_values = {
                   '1-sensor': 1,
                   '3-sensor': 3
                  }


class RoleEnumType(EnumTypeBase):
    name_values = {
                    'athlete': 1,
                    'manager': 2,
                    'admin': 3,
                    'super_admin': 4,
                    'biometrix_admin': 5,
                    'subject': 6,
                    'consumer': 7
                  }


class GenderEnumType(EnumTypeBase):
    name_values = {
                    'male': 1,
                    'female': 2,
                    'mixed': 3,
                    'other': 4
                  }


class AthleteStatusEnumType(EnumTypeBase):
    name_values = {
                    'competing':1,
                    'training': 2,
                    'returning': 3,
                    'injured': 4
                  }


class PushTypeEnumType(EnumTypeBase):
    name_values = {
                   'ios': 1,
                   'android': 2
                  }


class UsersPostgres(Base):
    __tablename__ = "users"

    id = Column(String, server_default=text("uuid_generate_v4()"), primary_key=True) # uuid NOT NULL DEFAULT uuid_generate_v4(),
    email = Column(String) # character varying COLLATE pg_catalog."default",
    facebook_id = Column(String)  # character varying COLLATE pg_catalog."default",
    auth_token = Column(String) # character varying COLLATE pg_catalog."default",
    first_name = Column(String) # character varying COLLATE pg_catalog."default",
    last_name = Column(String) #character varying COLLATE pg_catalog."default",
    phone_number = Column(String) #character varying COLLATE pg_catalog."default",
    password_digest = Column(String) #character varying COLLATE pg_catalog."default",
    created_at = Column(DateTime) #timestamp without time zone NOT NULL,
    updated_at = Column(DateTime) #timestamp without time zone NOT NULL,
    avatar_file_name = Column(String) #character varying COLLATE pg_catalog."default",
    avatar_content_type = Column(String) # charatacter varying COLLATE pg_catalog."default",
    avatar_file_size = Column(Integer) #integer,
    avatar_updated_at = Column(DateTime) #timestamp without time zone,
    position = Column(String) # character varying COLLATE pg_catalog."default",
    role = Column(RoleEnumType) #values_callable=lambda x: [e.value for e in x])) # integer
    active = Column(Boolean) # boolean DEFAULT true,
    in_training = Column(Boolean) #boolean,
    deleted_at = Column(DateTime) #timestamp without time zone,
    height_feet = Column(Integer) #integer,
    height_inches = Column(Integer) #integer,
    weight = Column(Integer) # integer,
    gender = Column(GenderEnumType) # integer,
    status = Column(AthleteStatusEnumType) # integer,
    push_token = Column(String) # character varying COLLATE pg_catalog."default",
    push_type = Column(PushTypeEnumType) # integer,
    onboarded = Column(Boolean) # boolean DEFAULT false,
    birthday = Column(String) # character varying COLLATE pg_catalog."default",
    organization_id = Column(String) # uuid,
    primary_training_group_id = Column(String) # uuid,
    year_in_school = Column(Integer) #  integer
    zip_code = Column(String)
    account_type = Column(AccountEnumType)
    account_status = Column(AccountStatusEnumType)
    system_type = Column(SystemTypeEnumType)
    sensor_pid = Column(String)
    mobile_udid = Column(String)
    injury_status = Column(InjuryStatusEnumtype)
    onboarding_status = Column(ARRAY(String))
    agreed_terms_of_use = Column(Boolean) # TODO: Move to DateTime Terms were Agreed to
    agreed_privacy_policy = Column(Boolean) # TODO: Move to DateTime Privacy Policy was agreed to
    cleared_to_play = Column(Boolean)
