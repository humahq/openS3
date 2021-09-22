import os

class Config:
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", default="")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", default="")
    AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", default="")
    AWS_REGION = os.getenv("AWS_REGION", default="us-east-1")
    # default UTTERANCE_CONFIG_BUCKET is for 009-dev while waiting for devops changes to occur
    CONFIG_BUCKET = os.getenv("UTTERANCE_CONFIG_BUCKET", default="")
    CONFIG_PATH = os.getenv("UTTERANCE_CONFIG_PATH", default="")
    pass