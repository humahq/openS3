# get keys, bucket name, and encoding from env
ENCODING = 'utf-8'

CONTENT_TYPES = {
    "bmp": "image/bmp",
    "css": "text/css",
    "gif": "image/gif",
    "html": "text/html",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "json": "application/json",
    "mp3": "audio/mpeg",
    "pdf": "application/pdf",
    "png": "image/png",
    "rtf": "text/rtf",
    "txt": "text/plain",
    "tiff": "image/tiff",
    "zip": "application/zip"
}

# AWS Datetime Format:  Wed, 28 Oct 2009 22:32:00 GMT
AWS_DATETIME_FORMAT = '%a, %d %b %Y %X %Z'

VALID_MODES = {
    'rb': 'read',
    'wb': 'write',
    'ab': 'append'
}

DEFAULT_CONTENT_TYPE = 'binary/octet-stream'

OBJECT_URL_SCHEME = 'https'

# http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
AWS_S3_REGION = 'us-east-1'

AWS_S3_SERVICE = 's3'