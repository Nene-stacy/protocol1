from setuptools import setup, find_packages

setup(
    name="double-ratchet",
    version="1.0.0",
    description="Signal Double Ratchet Algorithm — advanced Python implementation",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
