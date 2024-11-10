from setuptools import setup, find_packages

import certbot_dns_dreamhost

with open("Readme.md") as f:
    long_description = f.read()

setup(
    name="certbot_dns_dreamhost",
    version=certbot_dns_dreamhost.__version__,
    author="shadyproject",
    url="https://github.com/shadyproject/certbot_dns_dreamhost",
    description="Plugin for certbot to obtain certificates using a DNS TXT record for Dreamhost domains",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Unlicense",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: The Unlicense (Unlicense)",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Utilities",
        "Topic :: System :: Systems Administration",
    ],
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "setuptools>=41.6.0",
        "certbot>=1.18.0,<4.0",
        "dreamhostapi>=0.1.0",
        "dnspython>=2.0.0,<3.0",
        "tldextract>=5.1.2,<6.0",
    ],
    entry_points={
        "certbot.plugins": [
            "dns-dreamhost = certbot_dns_dreamhost.cert.client:Authenticator",
        ]
    },
)
