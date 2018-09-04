from sqlalchemy import Column, String, DateTime, text, ARRAY
from db_connection import Base 
from serialisable import Serialisable

class SessionPostgres(Base):
    __tablename__ = "session_events"

    id = Column(String, server_default=text("uuid_generate_v4()"), primary_key=True) # uuid NOT NULL DEFAULT uuid_generate_v4(),
    user_id = Column(String) # character varying COLLATE pg_catalog."default",
    created_at = Column(DateTime) #timestamp without time zone NOT NULL,
    updated_at = Column(DateTime) #timestamp without time zone NOT NULL,
    happened_at = Column(DateTime)
    training_group_ids = Column(ARRAY(String))
    sensor_data_filename = Column(String)



class SessionDDB(Serialisable):

    def __init__(self, *,
                 event_date,
                 end_date=None,
                 session_status=None,
                 created_date,
                 updated_date,
                 session_id=None,
                 user_id,
                 version='2.3',
                 s3_files=set(),
                 training_group_ids
                 ):
        self.session_id = session_id
        self.event_date = event_date
        self.end_date = end_date
        self.session_status = session_status
        self.created_date = created_date
        self.updated_date = updated_date
        self.version = version
        self.s3_files = s3_files

        self.accessory_id = None
        self.sensor_ids = set()
        self.user_id = user_id
        self.user_mass = None
        self.team_id = None
        self.training_group_ids = set(training_group_ids) 


    def json_serialise(self):
        ret = {
            'id': self.session_id,
            'accessory_id': self.accessory_id,
            'sensor_ids': self.sensor_ids,
            'user_id': self.user_id,
            'user_mass': self.user_mass,
            'team_id': self.team_id,
            'training_group_ids': self.training_group_ids,
            'event_date': self.event_date,
            'session_status': self.session_status,
            'end_date': self.end_date,
            'created_date': self.created_date,
            'updated_date': self.updated_date,
            's3_files': self.s3_files
        }
        return {k: v for k, v in ret.items() if v}
