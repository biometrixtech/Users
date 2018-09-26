import json
import os
import re

from ..utils.xray import xray_recorder, TraceHeader
from .config import Config
from .flask_app import app


def handler(event, context):
    if os.environ['ENVIRONMENT'] != 'production':
        print(json.dumps(event))

    # Strip mount point and version information from the path
    path_match = re.match(f'^/(?P<mount>({os.environ["SERVICE"]}|v1))?(/(?P<version>(\d+([._]\d+([._]\d+(-\w+([._]\d+)?)?)?)?)|latest))?(?P<path>/.+?)/?$', event['path'])
    if path_match is None:
        raise Exception('Invalid path')
    event['path'] = path_match.groupdict()['path']
    api_version = path_match.groupdict()['version']
    Config.set('API_VERSION', api_version)

    # Pass tracing info to X-Ray
    if 'X-Amzn-Trace-Id-Safe' in event['headers']:
        xray_trace = TraceHeader.from_header_str(event['headers']['X-Amzn-Trace-Id-Safe'])
        xray_recorder.begin_segment(
            name='{SERVICE}.{ENVIRONMENT}.fathomai.com'.format(**os.environ),
            traceid=xray_trace.root,
            parent_id=xray_trace.parent
        )
    else:
        xray_recorder.begin_segment(name='{SERVICE}.{ENVIRONMENT}.fathomai.com'.format(**os.environ))

    xray_recorder.current_segment().put_http_meta('url', f"https://{event['headers']['Host']}/{os.environ['SERVICE']}/{api_version}{event['path']}")
    xray_recorder.current_segment().put_http_meta('method', event['httpMethod'])
    xray_recorder.current_segment().put_http_meta('user_agent', event['headers']['User-Agent'])
    xray_recorder.current_segment().put_annotation('environment', os.environ['ENVIRONMENT'])
    xray_recorder.current_segment().put_annotation('version', str(api_version))

    ret = app(event, context)
    ret['headers'].update({
        'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Origin': '*',
    })

    # Unserialise JSON output so AWS can immediately serialise it again...
    ret['body'] = ret['body'].decode('utf-8')

    if ret['headers']['Content-Type'] == 'application/octet-stream':
        ret['isBase64Encoded'] = True

    # xray_recorder.current_segment().http['response'] = {'status': ret['statusCode']}
    xray_recorder.current_segment().put_http_meta('status', ret['statusCode'])
    xray_recorder.current_segment().apply_status_code(ret['statusCode'])
    xray_recorder.end_segment()

    if os.environ['ENVIRONMENT'] != 'production':
        print(json.dumps(ret))
    return ret