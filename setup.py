"""
Setup configuration for CredLock
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="credlock",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="🔐 Prevent accidental credential commits to Git",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/credlock",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Version Control",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=[
        "typer[all]>=0.9.0",
        "rich>=13.7.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "credlock=credlock.cli:app",
        ],
    },
    keywords="security credential secret git pre-commit detection",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/credlock/issues",
        "Source": "https://github.com/yourusername/credlock",
    },
)