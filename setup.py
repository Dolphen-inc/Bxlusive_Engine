from setuptools import setup, find_packages

# Safely try to import pybind11 helpers for the build phase
try:
    from pybind11.setup_helpers import PyBind11Extension, build_ext
    has_pybind11 = True
except ImportError:
    has_pybind11 = False
    PyBind11Extension = object  # Dummy fallback for metadata inspection
    build_ext = object

ext_modules = []
if has_pybind11:
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
    name="Bxlusive",
    version="1.0.0",
    description="High-performance custom zero-dependency cryptography library",
    long_description=open("README.md", encoding="utf-8").read() if "README.md" in __import__("os").listdir(".") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext} if has_pybind11 else {},
    python_requires=">=3.8",
    install_requires=[
        "pybind11>=2.6.0"
    ],
    zip_safe=False,
)
