from setuptools import setup, find_packages
import os

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='trustauthx',
    version='0.4.44',
    description='Official connector SDK for TrustAuthx',
    long_description=long_description,
    long_description_content_type='text/markdown',  # This is important!
    author='moonlightnexus',
    author_email='nexus@trustauthx.com',
    url="https://github.com/One-Click-Auth/TrustAuthx-Py-SDK.git",
    license="MIT",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.9',
                ],
    packages=find_packages(),
    install_requires=[
        "certifi>=2023.5.7",
        "cffi>=1.15.1",
        "cryptography==3.4.8",
        "ecdsa>=0.18.0",
        "idna>=3.4",
        "pyasn1>=0.5.0",
        "pycparser>=2.21",
        "requests>=2.31.0",
        "rsa>=4.9",
        "six>=1.16.0",
        "urllib3<=3.0.0",
        "charset-normalizer>=3.2.0",
        "python-jose>=3.3.0",
        "python-dotenv==1.0.0"
                     ],
    entry_points={
        'console_scripts': [
            'trustauthx = trustauthx.cli:main',
        ],
    },
)
