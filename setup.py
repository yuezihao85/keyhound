"""Packaging for keyhound (setuptools; no runtime dependencies)."""

import os

from setuptools import find_packages, setup

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "README.md"), "r", encoding="utf-8") as handle:
    LONG = handle.read()

setup(
    name="keyhound",
    version="0.1.0",
    description="Zero-dependency secret scanner for repos, pre-commit and CI",
    long_description=LONG,
    long_description_content_type="text/markdown",
    author="yuezihao85",
    url="https://github.com/yuezihao85/keyhound",
    license="MIT",
    packages=find_packages(exclude=("tests", "tests.*")),
    python_requires=">=3.7",
    install_requires=[],
    extras_require={"dev": ["pytest>=6"]},
    entry_points={"console_scripts": ["keyhound=keyhound.cli:main"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="secrets scanner entropy sarif pre-commit ci security",
    project_urls={
        "Source": "https://github.com/yuezihao85/keyhound",
        "Issues": "https://github.com/yuezihao85/keyhound/issues",
    },
)
