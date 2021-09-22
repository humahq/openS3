"""Setup.py for openS3"""

from setuptools import setup, find_packages

# Pull in the package info
package_name = 'openS3'
package = __import__(package_name)
version = package.__version__
author = package.__author__
email = package.__email__

setup(
    name=package_name,
    version=version,
    description='A pythonic way to open s3 files',
    author=author,
    author_email=email,
    maintainer=author,
    maintainer_email=email,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
    'aws-requests-auth',
    'PyYAML',
    'aws-requests-auth'
    ],
    license='Proprietary',
    keywords='',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: Proprietary',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython'
    ],
)
