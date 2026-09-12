"""
Setup script for Guardian Agent
"""

from setuptools import setup, find_packages

setup(
    name="guardian-agent",
    version="1.0.0",
    description="AI Security Guardian - Monitor AI model permissions",
    author="Your Team",
    packages=find_packages(),
    install_requires=[
        'psutil>=5.9.0',
        'rich>=13.5.0',
        'textual>=0.41.0',
        'tabulate>=0.9.0',
        'colorama>=0.4.6',
        'openai>=1.0.0',
        'google-generativeai>=0.3.0',
        'requests>=2.31.0',
        'websocket-client>=1.5.0',
    ],
    entry_points={
        'console_scripts': [
            'guardian=src.main:main',
        ],
    },
    python_requires='>=3.8',
)