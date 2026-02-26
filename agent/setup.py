"""Setup script for the RAID Monitor Agent package."""

from setuptools import setup, find_packages

setup(
    name="raid-agent",
    version="1.1.7",
    description="RAID Monitor Agent - collects RAID controller data via storcli64",
    long_description=(
        "A daemon that collects RAID controller health data using storcli64 "
        "(MegaRAID/PERC) and reports it to a central RAID monitoring server. "
        "Supports auto-registration, self-update, and SELinux."
    ),
    author="RAID Monitor Team",
    author_email="admin@raid-monitor.example.com",
    url="https://raid-monitor.example.com",
    license="Proprietary",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.4",
    ],
    entry_points={
        "console_scripts": [
            "raid-agent=raid_agent.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
)
