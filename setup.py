#!/usr/bin/env python
# -*- coding: utf-8 -*-

import setuptools

with open("README.md", "r") as fd:
    long_description = fd.read()

setuptools.setup(
    name="sipcounter",
    version="0.0.2",
    author="Szabolcs Szokoly",
    author_email="szokoly@protonmail.com",
    maintainer="Szabolcs Szokoly",
    maintainer_email="sszokoly@protonmail.com",
    license="MIT",
    url="https://github.com/sszokoly/sipcounter",
    description="SIP message counter",
    long_description=long_description,
    long_description_content_type="text/markdown",
    py_modules=["sipcounter"],
    python_requires=">=2.7",
    keywords="VoIP telephony SIP protocol message counter",
    install_requires=[],
    classifiers=[
        "Environment :: Console",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Telephony",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
    ],
)
