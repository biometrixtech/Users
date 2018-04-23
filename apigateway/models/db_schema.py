# coding: utf-8
from sqlalchemy import ARRAY, Boolean, Column, Date, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Table, Text, text
from sqlalchemy.dialects.postgresql.base import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()
metadata = Base.metadata


t_accessories = Table(
    'accessories', metadata,
    Column('id', String, index=True),
    Column('organization_id', UUID),
    Column('last_user_id', UUID),
    Column('hw_model', String),
    Column('firmware_version', String),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    Column('team_id', UUID),
    Column('name', String),
    Column('operating_mode', String),
    Column('state', String),
    Column('battery_level', Float(53)),
    Column('serial_number', String),
    Column('memory_level', Float(53))
)


class ActiveAdminComment(Base):
    __tablename__ = 'active_admin_comments'
    __table_args__ = (
        Index('index_active_admin_comments_on_author_type_and_author_id', 'author_type', 'author_id'),
        Index('index_active_admin_comments_on_resource_type_and_resource_id', 'resource_type', 'resource_id')
    )

    id = Column(Integer, primary_key=True, server_default=text("nextval('active_admin_comments_id_seq'::regclass)"))
    namespace = Column(String, index=True)
    body = Column(Text)
    resource_id = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    author_id = Column(Integer)
    author_type = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    msg = Column(String)
    team_id = Column(UUID)
    related_user_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class ArInternalMetadatum(Base):
    __tablename__ = 'ar_internal_metadata'

    key = Column(String, primary_key=True)
    value = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AthletePermission(Base):
    __tablename__ = 'athlete_permissions'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    athlete_id = Column(UUID, index=True)
    user_id = Column(UUID, index=True)
    permitted_operation = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


t_base_anatomical_calibration_events_sensors = Table(
    'base_anatomical_calibration_events_sensors', metadata,
    Column('base_anatomical_calibration_event_id', UUID),
    Column('sensor_id', String)
)


t_block_events_sensors = Table(
    'block_events_sensors', metadata,
    Column('sensor_id', String, index=True),
    Column('block_event_id', UUID, index=True),
    Index('index_block_events_sensors_on_sensor_id_and_block_event_id', 'sensor_id', 'block_event_id')
)


t_blocks_exercises = Table(
    'blocks_exercises', metadata,
    Column('block_id', UUID, index=True),
    Column('exercise_id', UUID, index=True),
    Index('index_blocks_exercises_on_block_id_and_exercise_id', 'block_id', 'exercise_id')
)


class DeviceStage(Base):
    __tablename__ = 'device_stages'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    hw_id = Column(String)
    firmware_stage_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class FirmwareStage(Base):
    __tablename__ = 'firmware_stages'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    firmware_id = Column(UUID)
    stage = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Firmware(Base):
    __tablename__ = 'firmwares'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    device_type = Column(Integer)
    version = Column(String)
    file_file_name = Column(String)
    file_content_type = Column(String)
    file_file_size = Column(Integer)
    file_updated_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    notes = Column(Text)


class Injury(Base):
    __tablename__ = 'injuries'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    description = Column(String)
    user_id = Column(UUID)
    happened_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String)
    body_part = Column(Integer)
    returned_at = Column(Date)
    result_of_impact = Column(Boolean)
    treatment = Column(Integer)


t_movement = Table(
    'movement', metadata,
    Column('session_event_id', UUID, index=True)
)


class OauthAccessGrant(Base):
    __tablename__ = 'oauth_access_grants'

    id = Column(Integer, primary_key=True, server_default=text("nextval('oauth_access_grants_id_seq'::regclass)"))
    application_id = Column(ForeignKey('oauth_applications.id'), nullable=False)
    token = Column(String, nullable=False, unique=True)
    expires_in = Column(Integer, nullable=False)
    redirect_uri = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime)
    scopes = Column(String)
    resource_owner_id = Column(UUID)

    application = relationship('OauthApplication')


class OauthAccessToken(Base):
    __tablename__ = 'oauth_access_tokens'

    id = Column(Integer, primary_key=True, server_default=text("nextval('oauth_access_tokens_id_seq'::regclass)"))
    application_id = Column(ForeignKey('oauth_applications.id'))
    token = Column(String, nullable=False, unique=True)
    refresh_token = Column(String, unique=True)
    expires_in = Column(Integer)
    revoked_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    scopes = Column(String)
    previous_refresh_token = Column(String, nullable=False, server_default=text("''::character varying"))
    resource_owner_id = Column(UUID)

    application = relationship('OauthApplication')


class OauthApplication(Base):
    __tablename__ = 'oauth_applications'

    id = Column(Integer, primary_key=True, server_default=text("nextval('oauth_applications_id_seq'::regclass)"))
    name = Column(String, nullable=False)
    uid = Column(String, nullable=False, unique=True)
    secret = Column(String, nullable=False)
    redirect_uri = Column(Text, nullable=False)
    scopes = Column(String, nullable=False, server_default=text("''::character varying"))
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Order(Base):
    __tablename__ = 'orders'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    user_id = Column(UUID)
    items = Column(JSON, server_default=text("'{}'::json"))
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    team_id = Column(UUID)
    woocommerce_order_id = Column(String, index=True)
    organization_id = Column(UUID)
    woocommerce_customer_id = Column(Integer)


class Organization(Base):
    __tablename__ = 'organizations'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    address = Column(String)
    address_two = Column(String)
    city = Column(String)
    state = Column(String)
    zip = Column(String)
    team_count = Column(Integer)


class ReadMark(Base):
    __tablename__ = 'read_marks'
    __table_args__ = (
        Index('read_marks_reader_readable_index', 'reader_id', 'reader_type', 'readable_type', 'readable_id', unique=True),
    )

    id = Column(Integer, primary_key=True, server_default=text("nextval('read_marks_id_seq'::regclass)"))
    readable_id = Column(UUID)
    readable_type = Column(String)
    reader_id = Column(UUID)
    reader_type = Column(String)
    timestamp = Column(DateTime)


class RpushApp(Base):
    __tablename__ = 'rpush_apps'

    id = Column(Integer, primary_key=True, server_default=text("nextval('rpush_apps_id_seq'::regclass)"))
    name = Column(String, nullable=False)
    environment = Column(String)
    certificate = Column(Text)
    password = Column(String)
    connections = Column(Integer, nullable=False, server_default=text("1"))
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    type = Column(String, nullable=False)
    auth_key = Column(String)
    client_id = Column(String)
    client_secret = Column(String)
    access_token = Column(String)
    access_token_expiration = Column(DateTime)


class RpushFeedback(Base):
    __tablename__ = 'rpush_feedback'

    id = Column(Integer, primary_key=True, server_default=text("nextval('rpush_feedback_id_seq'::regclass)"))
    device_token = Column(String(64), nullable=False, index=True)
    failed_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    app_id = Column(Integer)


class RpushNotification(Base):
    __tablename__ = 'rpush_notifications'
    __table_args__ = (
        Index('index_rpush_notifications_multi', 'delivered', 'failed'),
    )

    id = Column(Integer, primary_key=True, server_default=text("nextval('rpush_notifications_id_seq'::regclass)"))
    badge = Column(Integer)
    device_token = Column(String(64))
    sound = Column(String, server_default=text("'default'::character varying"))
    alert = Column(Text)
    data = Column(Text)
    expiry = Column(Integer, server_default=text("86400"))
    delivered = Column(Boolean, nullable=False, server_default=text("false"))
    delivered_at = Column(DateTime)
    failed = Column(Boolean, nullable=False, server_default=text("false"))
    failed_at = Column(DateTime)
    error_code = Column(Integer)
    error_description = Column(Text)
    deliver_after = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    alert_is_json = Column(Boolean, server_default=text("false"))
    type = Column(String, nullable=False)
    collapse_key = Column(String)
    delay_while_idle = Column(Boolean, nullable=False, server_default=text("false"))
    registration_ids = Column(Text)
    app_id = Column(Integer, nullable=False)
    retries = Column(Integer, server_default=text("0"))
    uri = Column(String)
    fail_after = Column(DateTime)
    processing = Column(Boolean, nullable=False, server_default=text("false"))
    priority = Column(Integer)
    url_args = Column(Text)
    category = Column(String)
    content_available = Column(Boolean, server_default=text("false"))
    notification = Column(Text)


class SchemaMigration(Base):
    __tablename__ = 'schema_migrations'

    version = Column(String, primary_key=True)


class Season(Base):
    __tablename__ = 'seasons'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    starts_at = Column(Date)
    finishes_at = Column(Date)
    team_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String)


t_sensors = Table(
    'sensors', metadata,
    Column('id', String, index=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    Column('team_id', UUID),
    Column('last_magnetometer_calibrated', Boolean),
    Column('last_user_id', UUID),
    Column('hw_model', String),
    Column('firmware_version', String),
    Column('clock_drift', Integer),
    Column('memory_level', Float(53))
)


t_sensors_session_anatomical_calibration_events = Table(
    'sensors_session_anatomical_calibration_events', metadata,
    Column('session_anatomical_calibration_event_id', UUID, index=True),
    Column('sensor_id', String, index=True),
    Index('aces_acei_si', 'session_anatomical_calibration_event_id', 'sensor_id', unique=True)
)


t_sensors_session_events = Table(
    'sensors_session_events', metadata,
    Column('sensor_id', String, index=True),
    Column('session_event_id', UUID, index=True),
    Index('index_sensors_session_events_on_session_event_id_and_sensor_id', 'session_event_id', 'sensor_id', unique=True)
)


t_sensors_training_events = Table(
    'sensors_training_events', metadata,
    Column('sensor_id', String, index=True),
    Column('training_event_id', UUID, index=True),
    Index('sensors_te_sensor_id_te_id', 'sensor_id', 'training_event_id', unique=True)
)


t_sensors_unmatched_events = Table(
    'sensors_unmatched_events', metadata,
    Column('unmatched_event_id', UUID, index=True),
    Column('sensor_id', UUID, index=True),
    Index('sue_si_uei', 'sensor_id', 'unmatched_event_id')
)


class SessionAnatomicalCalibrationEvent(Base):
    __tablename__ = 'session_anatomical_calibration_events'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    happened_at = Column(DateTime)
    sensor_data_filename = Column(String, index=True)
    training_session_log_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    user_id = Column(UUID)
    session_ac_success = Column(Boolean)
    rf_n_transform = Column(ARRAY(DOUBLE_PRECISION(precision=53)), server_default=text("'{}'::double precision[]"))
    failure_type = Column(Integer)
    placement_lf = Column(String)
    placement_rf = Column(String)
    placement_h = Column(String)


class SessionEvent(Base):
    __tablename__ = 'session_events'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    happened_at = Column(DateTime)
    user_id = Column(UUID)
    training_session_log_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    sensor_data_filename = Column(String, index=True)
    session_anatomical_calibration_event_id = Column(UUID)
    session_success = Column(Boolean)
    session_rpe = Column(Integer)
    hip_n_transform = Column(ARRAY(DOUBLE_PRECISION(precision=53)), server_default=text("'{}'::double precision[]"))
    session_type = Column(Integer)
    training_group_ids = Column(ARRAY(UUID()), server_default=text("'{}'::uuid[]"))
    upload_completed = Column(Boolean, server_default=text("false"))
    part_numbers = Column(ARRAY(INTEGER()), server_default=text("'{}'::integer[]"))
    ended_at = Column(DateTime)
    sensor1_id = Column(String)
    sensor1_gyro_offset = Column(ARRAY(DOUBLE_PRECISION(precision=53)), server_default=text("'{}'::double precision[]"))
    sensor1_clock_set_happened_at = Column(DateTime)
    sensor2_id = Column(String)
    sensor2_gyro_offset = Column(ARRAY(DOUBLE_PRECISION(precision=53)), server_default=text("'{}'::double precision[]"))
    sensor2_clock_set_happened_at = Column(DateTime)
    sensor3_id = Column(String)
    sensor3_gyro_offset = Column(ARRAY(DOUBLE_PRECISION(precision=53)), server_default=text("'{}'::double precision[]"))
    sensor3_clock_set_happened_at = Column(DateTime)


class SetLog(Base):
    __tablename__ = 'set_logs'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    reps = Column(Integer)
    weight = Column(Integer)
    exercise_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Sport(Base):
    __tablename__ = 'sports'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    positions = Column(ARRAY(VARCHAR()), server_default=text("'{}'::character varying[]"))
    active = Column(Boolean)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Subscription(Base):
    __tablename__ = 'subscriptions'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    tier = Column(Integer)
    athlete_subscriptions = Column(Integer)
    order_id = Column(UUID)
    organization_id = Column(UUID)
    user_id = Column(UUID)
    team_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    active = Column(Boolean)
    woocommerce_subscription_id = Column(Integer, index=True)
    sku = Column(String)


class Team(Base):
    __tablename__ = 'teams'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    organization_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    athlete_subscriptions = Column(Integer)
    athlete_manager_subscriptions = Column(Integer)
    gender = Column(Integer)
    sport_id = Column(UUID)


t_teams_users = Table(
    'teams_users', metadata,
    Column('team_id', UUID, index=True),
    Column('user_id', UUID, index=True),
    Index('index_teams_users_on_team_id_and_user_id', 'team_id', 'user_id')
)


class TrainingGroupLog(Base):
    __tablename__ = 'training_group_logs'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    user_id = Column(UUID)
    training_group_id = Column(UUID)
    event_type = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    manager_id = Column(UUID)


class TrainingGroup(Base):
    __tablename__ = 'training_groups'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    team_id = Column(UUID)
    user_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String)
    description = Column(String)
    active = Column(Boolean, server_default=text("true"))
    tier = Column(Integer)
    manager_id = Column(UUID)


t_training_groups_users = Table(
    'training_groups_users', metadata,
    Column('training_group_id', UUID, index=True),
    Column('user_id', UUID, index=True),
    Index('index_training_groups_users_on_training_group_id_and_user_id', 'training_group_id', 'user_id')
)


class TrainingSessionLog(Base):
    __tablename__ = 'training_session_logs'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    started_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    user_id = Column(UUID)
    team_regimen_id = Column(UUID)
    training_group_id = Column(UUID)
    finished_at = Column(DateTime)


class UserQuestion(Base):
    __tablename__ = 'user_questions'

    id = Column(Integer, primary_key=True, server_default=text("nextval('user_questions_id_seq'::regclass)"))
    question = Column(String)
    question_id = Column(UUID)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    keywords = Column(ARRAY(VARCHAR()), server_default=text("'{}'::character varying[]"))
    interested_parties = Column(ARRAY(VARCHAR()), server_default=text("'{}'::character varying[]"))


class User(Base):
    __tablename__ = 'users'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    email = Column(String, index=True)
    facebook_id = Column(String)
    auth_token = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    phone_number = Column(String)
    password_digest = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    avatar_file_name = Column(String)
    avatar_content_type = Column(String)
    avatar_file_size = Column(Integer)
    avatar_updated_at = Column(DateTime)
    position = Column(String)
    role = Column(Integer)
    active = Column(Boolean, server_default=text("true"))
    in_training = Column(Boolean)
    deleted_at = Column(DateTime, index=True)
    height_feet = Column(Integer)
    height_inches = Column(Integer)
    weight = Column(Integer)
    gender = Column(Integer)
    status = Column(Integer)
    push_token = Column(String)
    push_type = Column(Integer)
    onboarded = Column(Boolean, server_default=text("false"))
    birthday = Column(String)
    organization_id = Column(UUID)
    primary_training_group_id = Column(UUID)
    year_in_school = Column(Integer)
