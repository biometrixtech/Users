import enum
from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, ForeignKey, Enum, text
from db_connection import Base
from sqlalchemy import types


# TODO: Refactor Enums to use mixins

class AccountEnum(enum.Enum):
    paid = 0
    free = 1


class AccountEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        return AccountEnum[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        return AccountEnum(value).name    # Convert an integer to a name


class AccountStatusEnum(enum.Enum):
    active = 0
    pending = 1
    past_due = 2
    expired = 3


class AccountStatusEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        return AccountStatusEnum[value].value  # Convert name to an integer

    def process_result_value(self, value, dialect):
        return AccountStatusEnum(value).name  # Convert an integer to a name


class RoleEnum(enum.Enum):
    athlete = 1
    manager = 2
    admin = 3
    super_admin = 4
    biometrix_admin = 5
    subject = 6
    consumer = 7


class RoleEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        return RoleEnum[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        return RoleEnum(value).name    # Convert an integer to a name


class GenderEnum(enum.Enum):
    male = 1
    female = 2
    mixed = 3
    other = 4


class GenderEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        if value:
            return GenderEnum[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        if value:
            return GenderEnum(value).name    # Convert an integer to a name


class AthleteStatus(enum.Enum):
    competing = 1
    training = 2
    returning = 3
    injured = 4


class AthleteStatusEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        if value:
            return AthleteStatus[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        if value:
            return AthleteStatus(value).name    # Convert an integer to a name


class PushType(enum.Enum):
    ios = 1
    android = 2


class PushTypeEnumType(types.TypeDecorator):
    impl = types.Integer

    def process_bind_param(self, value, dialect):
        if value:
            return PushType[value].value    # Convert name to an integer

    def process_result_value(self, value, dialect):
        if value:
            return PushType(value).name    # Convert an integer to a name


class Users(Base):
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


"""
﻿-- Table: public.users

-- DROP TABLE public.users;

CREATE TABLE public.users
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    email character varying COLLATE pg_catalog."default",
    facebook_id character varying COLLATE pg_catalog."default",
    auth_token character varying COLLATE pg_catalog."default",
    first_name character varying COLLATE pg_catalog."default",
    last_name character varying COLLATE pg_catalog."default",
    phone_number character varying COLLATE pg_catalog."default",
    password_digest character varying COLLATE pg_catalog."default",
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    avatar_file_name character varying COLLATE pg_catalog."default",
    avatar_content_type character varying COLLATE pg_catalog."default",
    avatar_file_size integer,
    avatar_updated_at timestamp without time zone,
    "position" character varying COLLATE pg_catalog."default",
    role integer,
    active boolean DEFAULT true,
    in_training boolean,
    deleted_at timestamp without time zone,
    height_feet integer,
    height_inches integer,
    weight integer,
    gender integer,
    status integer,
    push_token character varying COLLATE pg_catalog."default",
    push_type integer,
    onboarded boolean DEFAULT false,
    birthday character varying COLLATE pg_catalog."default",
    organization_id uuid,
    primary_training_group_id uuid,
    year_in_school integer,
    zip_code character varying COLLATE pg_catalog."default",
    CONSTRAINT users_pkey PRIMARY KEY (id)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.users
    OWNER to biometrix_admin;

GRANT ALL ON TABLE public.users TO biometrix_admin;

GRANT SELECT ON TABLE public.users TO users_dev;

-- Index: index_users_on_deleted_at

-- DROP INDEX public.index_users_on_deleted_at;

CREATE INDEX index_users_on_deleted_at
    ON public.users USING btree
    (deleted_at)
    TABLESPACE pg_default;

-- Index: index_users_on_email

-- DROP INDEX public.index_users_on_email;

CREATE INDEX index_users_on_email
    ON public.users USING btree
    (email COLLATE pg_catalog."default")
    TABLESPACE pg_default;
"""
