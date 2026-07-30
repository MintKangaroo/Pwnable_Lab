"""Compatibility shim for older pip versions without reliable PEP 660 support."""

from setuptools import find_packages, setup


setup(
    name="pwnable-lab",
    version="1.0.0",
    description=(
        "A safe web playground for ELF analysis, exploit payload construction, "
        "and pwn challenges."
    ),
    packages=find_packages(include=["pwnable_lab", "pwnable_lab.*"]),
    python_requires=">=3.10",
    install_requires=[
        "alembic>=1.14,<2",
        "fastapi>=0.115,<1",
        "uvicorn[standard]>=0.30,<1",
        "python-multipart>=0.0.12,<1",
        "pydantic>=2.9,<3",
        "pydantic-settings>=2.5,<3",
        "SQLAlchemy>=2.0,<3",
        "psycopg[binary]>=3.2,<4",
        "capstone>=5.0,<6",
        "pyelftools>=0.31,<1",
    ],
    extras_require={
        "dev": [
            "black>=24.10,<27",
            "mypy>=1.13,<2",
            "pytest>=8,<10",
            "pytest-cov>=5,<8",
            "httpx>=0.27,<1",
            "ruff>=0.8,<1",
        ]
    },
)
