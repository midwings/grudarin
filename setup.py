"""
Grudarin - Setup
"""

from setuptools import setup, find_packages

setup(
    name="grudarin",
    version="1.1.8",
    description="Network Monitoring Tool with Force-Directed Graph and Vulnerability Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Grudarin Contributors",
    license="GPL-3.0 license",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "grudarin=grudarin.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    package_data={
        "": ["lua_rules/*.lua", "scanner/*.cpp"],
    },
)
