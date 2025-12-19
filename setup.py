from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "cryptocore=cryptocore.cli:main",
        ],
    },
    install_requires=[
        "pycryptodome>=3.10.1",
    ],
    python_requires=">=3.8",
)