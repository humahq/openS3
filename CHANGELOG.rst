Changelog
=========
0.3.0
-----

- Modified aws client so it could be run in AWS containers with assume role rights.
- Modify setup.py to install software instead of do tests.
- Remove tox.
- Repurpose Makefile for building app rather than run tox tests.
- Remove sphynx docs folder as this is a fork and will not be posted to the original.
- Remove method 'list_directory'
- Replaced auth mechanism
- Changed requests library to a higher level one.
- Added config.py to capture needed variables (useful for when running as a container in AWS)

0.2.0
-----

- Added ability to list contents of a "directory" on AWS S3. Directories in the context of OpenS3
  are object keys that end in a slash. Eg. "/static/css/"

0.1.5
-----

- Refactored :py:class:`~openS3.ctx_manager.OpenS3` into its own module, :py:mod:`~openS3.ctx_manager`.

0.1.4
-----

- Changed default ACL value to be *private*.
- Added :py:meth:`~openS3.ctx_manager.OpenS3.open` method.
- Updated :py:meth:`~openS3.ctx_manager.OpenS3.open` to able to be called with a dictionary of extra request headers.
- Defined specific modes in which an S3 object can be opened.

0.1.3
-----

- Updated docs with `Travis CI <https://travis-ci.org/logston/openS3>`_ badge.