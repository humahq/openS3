from contextlib import closing
from datetime import datetime
import hashlib
import hmac
from http.client import HTTPConnection, HTTPSConnection
import os
import urllib.parse
from wsgiref.handlers import format_date_time
from xml.etree import ElementTree
import requests
from aws_requests_auth.aws_auth import AWSRequestsAuth

from openS3.config import Config
from openS3.constants import (
    CONTENT_TYPES, ENCODING, VALID_MODES, DEFAULT_CONTENT_TYPE, OBJECT_URL_SCHEME,
    AWS_S3_REGION, AWS_S3_SERVICE)
from openS3.utils import (
    validate_values, b64_string, S3FileDoesNotExistError, S3IOError,
    get_canonical_query_string, get_canonical_headers_string,
    get_signing_key, hmac_sha256, uri_encode, get_dirs_and_files)


class OpenS3(object):
    """
    A context manager for interfacing with S3.
    """
    def __init__(self, 
                 bucket=Config.CONFIG_BUCKET,
                 access_key=Config.AWS_ACCESS_KEY_ID,
                 secret_key=Config.AWS_SECRET_ACCESS_KEY,
                 session_token=Config.AWS_SESSION_TOKEN):
        """
        Create a new context manager for interfacing with S3.

        :param bucket: An S3 bucket
        :param access_key: An AWS access key (eg. AEIFKEKWEFJFWA)
        :param secret_key: An AWS secret key.
        """
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        validate_values(validation_func=lambda value: value is not None, dic=locals())
        self.netloc = '{}.s3.amazonaws.com'.format(self.bucket)
        self.mode = 'rb'
        self.acl = 'private'
        self.auth = self._get_auth()

        # File like attributes
        self.object_key = ''
        self.buffer = ''
        self._content_type = None
        self.response_headers = {}
        self.extra_request_headers = {}

    def __call__(self, *args, **kwargs):
        return self.open(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_auth(self):
        auth = AWSRequestsAuth(aws_access_key=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_host=self.netloc,
            aws_region=Config.AWS_REGION,
            aws_service=AWS_S3_SERVICE,
            aws_token=self.session_token)
        return auth

    def read(self):
        """
        Return a bytes object with the contents of the remote S3 object.

        :rtype bytes:
        """
        self._get()
        return self.buffer

    def write(self, content):
        """
        Write content to file in S3.

        :param content:
        """
        if self.mode not in ('wb', 'ab'):
            raise RuntimeError('Must open file in write or append mode to write to file.')
        self.buffer = content
        # TODO handle multiple writes to same file.

    def open(self, object_key,
             mode='rb', content_type=None, acl='private', extra_request_headers=None):
        """
        Configure :py:class:`OpenS3` object to write to or read from a specific S3 object.

        :param object_key: A unique identifier for an object a bucket.
        :param mode: The mode in which the S3 object is opened. See Modes below.
        :param content_type: A standard MIME type describing the format of the contents.
        :param acl: Name of a specific canned Access Control List to apply to the object.

        **Modes**

        ====  ===================================================================
        mode  Description
        ====  ===================================================================
        'rb'  open for reading (default)
        'wb'  open for writing, truncating the file first
        'ab'  open for writing, appending to the end of the file if it exists
        ====  ===================================================================

        **Access Control List (acl)**

        Valid values include:

            - private  (*default*)
            - public-read
            - public-read-write
            - authenticated-read
            - bucket-owner-read
            - bucket-owner-full-control
        """
        if mode not in VALID_MODES:
            raise ValueError('{} is not a valid mode for opening an S3 object.'.format(mode))

        self.object_key = object_key
        self.mode = mode
        self.content_type = content_type
        self.acl = acl
        self.extra_request_headers = extra_request_headers if extra_request_headers else {}
        return self

    def close(self):
        if self.mode in ('wb', 'ab') and self.buffer:
            # TODO Does the old file need to be deleted
            # TODO from S3 before we write over it?
            self._put()
        # Reset OpenS3 object
        self.__init__()

    @property
    def content_type(self):
        """
        Return content_type of file. If file does not
        have a content_type, make a guess.
        """
        if self._content_type:
            return self._content_type

        # Check the response headers
        if 'Content-Type' in self.response_headers:
            return self.response_headers['Content-Type']

        content_type = DEFAULT_CONTENT_TYPE
        # get file extension
        if self.object_key:
            _, extension = os.path.splitext(self.object_key)
            extension = extension.strip('.')
            if extension in CONTENT_TYPES:
                # Make an educated guess about what the Content-Type should be.
                content_type = CONTENT_TYPES[extension]

        return content_type

    @content_type.setter
    def content_type(self, content_type):
        self._content_type = content_type

    @property
    def size(self):
        """
        Return the size of the buffer, in bytes.
        """
        # The file hasn't been retrieved from AWS, retrieve it.
        if not self.buffer and not self.response_headers:
            self._get()
        return str(len(self.buffer))  # TODO is this the right way to get size of buffer (bytes)?

    @property
    def url(self):
        """Return URL of resource"""
        scheme = OBJECT_URL_SCHEME
        path = self.object_key
        query = ''
        fragment = ''
        url_tuple = (scheme, self.netloc, path, query, fragment)
        return urllib.parse.urlunsplit(url_tuple)

    @property
    def md5hash(self):
        """Return the MD5 hash string of the file content"""
        digest = hashlib.md5(self.buffer.encode(ENCODING)).digest()
        return b64_string(digest)

    def _head(self):
        object_url = "https://" + self.netloc + "/" + self.object_key
        response = requests.head(object_url, auth=self.auth)
        return response

    def _get(self):
        """
        GET contents of remote S3 object.
        """
        object_url = "https://" + self.netloc + "/" + self.object_key
        response = requests.get(object_url, auth=self.auth)
        if response.status_code not in (200, 204):
            if response.length is None:
                    # length == None seems to be returned from GET requests
                    # to non-existing files
                    raise S3FileDoesNotExistError(self.object_key)
            raise S3IOError(
                'openS3 GET error. '
                'Response status: {}. '
                'Reason: {}.'.format(response.status_code, response.reason))
        else:
            self.buffer=response.text

    def _put(self):
        """PUT contents of file to remote S3 object."""
        object_url = "https://" + self.netloc + "/" + self.object_key
        response = requests.put(object_url, data=self.buffer, auth=self.auth)
        if response.status_code not in (200, 204):
            raise S3IOError(
                'openS3 PUT error. '
                'Response status: {}. '
                'Reason: {}.'.format(response.status_code, response.reason))
        else:
            return True

    def delete(self):
        """
        Remove file from its S3 bucket.
        """
        object_url = "https://" + self.netloc + "/" + self.object_key
        response = requests.delete(object_url, data=self.buffer, auth=self.auth)
        if response.status_code not in (200, 204):
            raise S3IOError(
                'openS3 PUT error. '
                'Response status: {}. '
                'Reason: {}.'.format(response.status_code, response.reason))
        self.__init__(self.bucket)

    def exists(self):
        """
        Return ``True`` if file exists in S3 bucket.
        """
        response = self._head()
        if response.status in (200, 404):
            return response.status == 200
        raise S3IOError(
            'openS3 HEAD error. '
            'Response status: {}. '
            'Reason: {}.\n'.format(response.status, response.reason))

def test():
    import yaml
    import json
    # get contents of local test file.
    source = "OpenS3/testfile.yml"
    destination = "testfile.json"
    testfile = open(os.getcwd() + "/" + source, "r")
    testfile_dict = {}
    try:
        testfile_dict = yaml.safe_load(testfile)
    except yaml.YAMLError as exc:
        exit(1)

    # create opens3 object
    openS3 = OpenS3(Config.CONFIG_BUCKET)

    # Write test file to s3 bucket
    object_key = Config.CONFIG_PATH + destination
    try:
        with openS3(object_key=object_key, content_type="text/plain", mode="wb") as f:
            f.write(json.dumps(testfile_dict))
    except S3IOError as e:
        print("Save of {} onto s3 failed because {}".format(object_key,e))

    # read test file from s3 bucket
    content: str = "{}"
    try:
        with openS3(object_key=object_key, content_type="text/plain", mode="rb") as f:
            content = f.read()
    except S3IOError as e:
        print("Fetch of {} from s3 failed because {}".format(object_key, e))

    # save file to yaml
    try:
        content_dict = json.loads(content)
    except:
        content_dict = '{}'
        print("file from s3 is not a json file")

    try:
        destination_out = "openS3/testfile_out.yml"
        file = open(destination_out, "w")
        yaml.dump(content_dict, file)
        file.close()
    except Exception as e:
        print("Save of {} onto file system failed because {}".format(destination, e))

    # save file to json
    try:
        destination_out = "openS3/testfile_out.json"
        file = open(destination_out, "w")
        file.write(content)
        file.close()
    except S3IOError as e:
        print("Save of {} failed because {}".format(destination, e))

    # print original file content after round trip to s3
    try:
        print(yaml.dump(content_dict, sort_keys=False, default_flow_style=False))
    except Exception as e:
        print("Save of {} onto file system failed because {}".format(destination, e))
    pass

if __name__ == '__main__':
    test()

