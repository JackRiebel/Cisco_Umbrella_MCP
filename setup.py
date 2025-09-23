from setuptools import setup, find_packages

setup(
    name="umbrella-mcp",
    version="0.1.0",
    description="A Python-based Model Context Protocol (MCP) server for Cisco Umbrella",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Jack Riebel",
    author_email="jack@example.com",
    url="https://github.com/JackRiebel/Umbrella_MCP",
    packages=find_packages(),
    install_requires=[
        "fastmcp>=0.1.0",
        "httpx>=0.23.0",
        "pydantic>=2.0.0",
        "python-dotenv>=0.21.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.18.0",
            "flake8>=5.0.0",
            "black>=22.0.0",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
