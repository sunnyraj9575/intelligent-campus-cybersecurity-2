from setuptools import find_packages, setup

setup(
    name="intelligent-campus-cyber-threat-detection",
    version="1.0.0",
    description="Supervised Machine Learning Cyber Security Threat Detection for University Campus Infrastructure",
    author="Campus Cyber Defense Research Lab",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scipy>=1.10.0",
        "scikit-learn>=1.3.0",
        "joblib>=1.3.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "pydantic>=2.0.0",
        "python-multipart>=0.0.6",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": ["pytest>=7.4.0"],
    },
)
