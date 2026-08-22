from setuptools import setup, find_packages
from pybind11.setup_helpers import PyBind11Extension, build_ext

ext_modules = [
    PyBind11Extension(
        "Bxlusive.bxlusive_core",
        [
            "csrc/chacha.cpp",
            "csrc/poly1305.cpp",
            "csrc/bindings.cpp"
        ],
        cxx_std=14,
    ),
]

setup(
    name="bxl-cryptography",
    version="1.0.1",  # <-- Bumped version because 1.0.0 is already taken
    description="High-performance custom zero-dependency cryptography library",
    long_description=open("README.md", encoding="utf-8").read() if "README.md" in __import__("os").listdir(".") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    python_requires=">=3.8",
    install_requires=[
        "pybind11>=2.6.0"
    ],
    zip_safe=False,
)
