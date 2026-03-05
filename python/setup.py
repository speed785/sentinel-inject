from setuptools import setup, find_packages

with open("../README.md", encoding="utf-8") as f:
    long_description = f.read()

_ = setup(
    name="sentinel-inject",
    version="0.1.0",
    author="sentinel-inject contributors",
    description="Prompt injection scanner middleware for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/speed785/sentinel-inject",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        # No hard runtime dependencies - all integrations are optional
    ],
    extras_require={
        "openai": ["openai>=1.0.0"],
        "anthropic": ["anthropic>=0.20.0"],
        "langchain": ["langchain-core>=0.1.0"],
        "all": [
            "openai>=1.0.0",
            "anthropic>=0.20.0",
            "langchain-core>=0.1.0",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio",
            "pytest-cov",
            "black",
            "ruff",
            "mypy",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Typing :: Typed",
    ],
    keywords=[
        "ai",
        "agent",
        "llm",
        "security",
        "prompt-injection",
        "middleware",
        "openai",
        "anthropic",
        "langchain",
        "safety",
        "scanner",
        "detection",
        "jailbreak",
    ],
)
