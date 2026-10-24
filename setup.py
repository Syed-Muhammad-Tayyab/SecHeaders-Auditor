from setuptools import setup, find_packages

setup(
    name="secheaders-auditor",
    version="1.0.0",
    description="Scan a website's HTTP security headers and get a hardening report.",
    author="Syed Muhammad Tayyab",
    url="https://github.com/Syed-Muhammad-Tayyab/SecHeaders-Auditor",
    packages=find_packages(),
    install_requires=["requests>=2.31.0"],
    entry_points={
        "console_scripts": [
            "secheaders=secheaders.cli:main",
        ],
    },
    python_requires=">=3.9",
)
