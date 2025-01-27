import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

setup(
    name="zgrab2_schemas",
    version="0.0.1",
    description="ZSchema definitions for zgrab2's JSON output.",
    classifiers=["Programming Language :: Python", "Natural Language :: English"],
    author="ZMap Team",
    author_email="team@zmap.io",
    url="https://github.com/zmap/zgrab2",
    keywords="zmap censys zgrab2 internet-wide scanning",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
