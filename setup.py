from pathlib import Path

from setuptools import find_packages, setup

from pigadget_mcp.version import VERSION


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")


setup(
    name="pigadget-mcp",
    version=VERSION,
    author="Belcarra",
    description="MCP service for Raspberry Pi USB gadget test systems",
    long_description=README,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    data_files=[
        ("share/pigadget-mcp/service", ["service/pigadget-mcp.service"]),
    ],
    python_requires=">=3.8",
    install_requires=[
        "mcp>=1.28.1,<2",
    ],
    entry_points={
        "console_scripts": [
            "pigadget-mcp=pigadget_mcp.server:main",
            "pigadget-mcp-install-service=pigadget_mcp.install_service:main",
        ],
    },
)
