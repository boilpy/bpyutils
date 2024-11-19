import os

import httpx

from upyog.util.environ import getenv
from upyog.util.string  import get_random_str
from upyog.util.eject   import ejectable
from upyog.api.base     import AsyncBaseClient, BaseClient

AWS_DEFAULT = {
    "service": "execute-api",
     "region": "us-west-2"
}

def is_lambda():
    return os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None

@ejectable(deps = ["getenv"])
def awsgetenv(*args, **kwargs):
    """
        Get AWS environment variables.

        Example
            >>> getenv("PROFILE")
            "default"
    """
    kwargs["prefix"] = "AWS"
    return getenv(*args, **kwargs)

@ejectable(deps = ["get_random_str"])
def get_aws_credentials(role = None, profile = None):
    import os.path as osp
    from configparser import ConfigParser
    import boto3

    if role:
        session = boto3.Session()
        sts     = session.client("sts")

        session_name = f"RoleSession-{get_random_str()}"

        assume_role  = sts.assume_role(
            RoleArn  = role,
            RoleSessionName = session_name,
        )

        assume_role_creds = assume_role["Credentials"]
        creds = {
            "aws_access_key_id": assume_role_creds["AccessKeyId"],
            "aws_secret_access_key": assume_role_creds["SecretAccessKey"],
            "aws_session_token": assume_role_creds["SessionToken"]
        }

        return { role: creds }
    else:
        path   = osp.join(osp.expanduser("~"), ".aws", "credentials")
        parser = ConfigParser()
        parser.read(path)

        creds  = { section: dict(parser[section])
            for section in parser.sections() }

        if "default" not in creds:
            kwargs = { "default": None }
            aws_access_key_id     = awsgetenv("ACCESS_KEY_ID", **kwargs)
            aws_secret_access_key = awsgetenv("SECRET_ACCESS_KEY", **kwargs)

            if aws_access_key_id and aws_secret_access_key:
                creds["default"] = {
                    "aws_access_key_id": aws_access_key_id,
                    "aws_secret_access_key": aws_secret_access_key,
                }

                aws_session_token = awsgetenv("SESSION_TOKEN", **kwargs)

                if aws_session_token:
                    creds["default"]["aws_session_token"] = aws_session_token
            else:
                session     = boto3.Session()
                credentials = session.get_credentials()

                creds["default"] = {
                    "aws_access_key_id": credentials.access_key,
                    "aws_secret_access_key": credentials.secret_key,
                    "aws_session_token": credentials.token,
                }

        if profile:
            assert profile in creds
            creds = creds[profile]

    return creds

@ejectable(imports = ["httpx"], globals_ = { "AWS_DEFAULT": AWS_DEFAULT })
class AWSSigV4Auth(httpx.Auth):
    requires_request_body = True

    def __init__(self,
        access_key,
        secret_key,
        token   = None,
        service = None,
        region  = None
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.token      = token

        self.service    = service or AWS_DEFAULT["service"]
        self.region     = region  or AWS_DEFAULT["region"]

    def auth_flow(self, r):
        from botocore.awsrequest  import AWSRequest
        from botocore.auth        import SigV4Auth
        from botocore.credentials import Credentials

        method  = r.method
        
        headers = { "Content-Type": "application/json" }

        aws_request = AWSRequest(
            method  = method,
            url     = str(r.url),
            headers = dict(headers),
            data    = r.content
        )
        credentials = Credentials(
            access_key = self.access_key,
            secret_key = self.secret_key,
            token      = self.token
        )
        aws_sigv4_auth = SigV4Auth(credentials, self.service, self.region)
        aws_sigv4_auth.add_auth(aws_request)

        r.headers.update(dict(aws_request.headers))

        yield r

@ejectable(deps = ["AsyncBaseClient", "AWSSigV4Auth", "awsgetenv", "get_aws_credentials"], globals_ = { "AWS_DEFAULT": AWS_DEFAULT })
class AWSClient(AsyncBaseClient):
    """
        AWSClient: AWS Client.

        Args:
            profile: AWS Profile.
            role: AWS Role.
            region: AWS Region.
            service: AWS Service.
    """
    def __init__(self,
        profile = None,
        role    = None,
        region  = None,
        service = None,
        *args, **kwargs
    ):
        super_   = super(AWSClient, self)
        super_.__init__(*args, **kwargs)

        role     = getenv("AWS_CLIENT_ROLE", default = role)

        if not self.auth:
            profile = str(profile or awsgetenv("PROFILE", default = "default"))
            aws_credentials = get_aws_credentials(role = role)

            if role:
                profile = role

            if profile not in aws_credentials:
                raise ValueError(f"Profile '{profile}' not found in AWS credentials.")
            
            region  = region or getattr(self, "region", AWS_DEFAULT["region"])
            assert region, "region is required."

            service = getattr(self, "service", service or AWS_DEFAULT["service"])
            assert service, "service is required."

            credentials = aws_credentials[profile]

            self.auth   = AWSSigV4Auth(
                access_key = credentials["aws_access_key_id"],
                secret_key = credentials["aws_secret_access_key"],
                token      = credentials.get("aws_session_token", None),
                service    = service,
                region     = region
            )

_BOTO3_SESSION = None
_BOTO3_CLIENT  = {}

@ejectable(globals_ = { "AWS_DEFAULT": AWS_DEFAULT, "_BOTO3_SESSION": _BOTO3_SESSION, "_BOTO3_CLIENT": _BOTO3_CLIENT })
def get_boto3_session(region_name=None):
    """
    Get a Boto3 Session. This function will globally cache the session.

    Args:
        region_name: AWS Region Name.
            (default: telemetry.config.DEFAULT["aws_region"])

    Returns:
        Boto3 Session.
    """
    import boto3
    global _BOTO3_SESSION
    if not _BOTO3_SESSION or not _BOTO3_SESSION.region_name == region_name:
        _BOTO3_SESSION = boto3.Session(
            region_name=region_name or AWS_DEFAULT["region"]
        )
    return _BOTO3_SESSION

@ejectable(globals_ = { "AWS_DEFAULT": AWS_DEFAULT }, deps = ["get_boto3_session"])
def get_boto3_client(service, region_name=None):
    """
    Get a Boto3 Client. This function will globally cache the client.

    Args:
        service: AWS Service Name.
        region: AWS Region Name.
            (default: telemetry.config.DEFAULT["aws_region"])

    Returns:
        Boto3 Client.
    """
    import boto3

    global _BOTO3_CLIENT
    
    region_name = region_name or AWS_DEFAULT["region"]
    key = f"{service}-{region_name}"
    
    if key not in _BOTO3_CLIENT:
        session = get_boto3_session(region_name=region_name)
        _BOTO3_CLIENT[key] = session.client(service)

    return _BOTO3_CLIENT[key]

@ejectable(deps = ["get_boto3_client"])
def invoke_lambda(fn_name, event):
    import json

    client   = get_boto3_client("lambda")
    response = client.invoke(
        FunctionName = fn_name,
        Payload      = json.dumps(event)
    )

    body = response["Payload"].read()

    try:
        response = json.loads(body)
    except json.JSONDecodeError:
        pass

    return response

@ejectable(deps = ["get_boto3_client"])
def check_ddb_update(tb_name, pk, sk, update):
    ddb = get_boto3_client("dynamodb")
    response = ddb.query(
        TableName = tb_name,
        KeyConditionExpression = "PK = :pk AND SK = :sk",
        ExpressionAttributeValues = {
            ":pk": { "S": pk },
            ":sk": { "S": sk }
        }
    )

    assert response["Count"] == 1

    item = response["Items"][0]

    checked = True

    for key, value in update.items():
        checked = checked and key in item
        
        for types in ("S", "BOOL"):
            if types in item[key]:
                checked = checked and item[key][types] == value
                break

        if "M" in item[key]:
            for sub_key, sub_value in value.items():
                checked = checked and sub_key in item[key]["M"]
                checked = checked and item[key]["M"][sub_key]["S"] == sub_value

    return checked

@ejectable(deps = ["get_boto3_client"])
def get_ddb_table_name(tb_name_pattern):
    import re

    ddb = get_boto3_client("dynamodb")
    response = ddb.list_tables()

    for tb_name in response["TableNames"]:
        if re.match(tb_name_pattern, tb_name):
            return tb_name

    raise ValueError(f"Table '{tb_name_pattern}' not found.")

# def get_sfn_arn(name):
    # return f"arn:aws:states:us-west-2:123456789012:stateMachine:{name}"

@ejectable(deps = ["get_boto3_client"])
def get_sfn_executions(name, from_, to):
    sfn      = get_boto3_client("stepfunctions")

    sfn_arn  = get_sfn_arn(name)

    response = sfn.list_executions(
        stateMachineArn = name,
        startDate = from_,
        endDate = to
    )

    return response["executions"]