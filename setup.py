from setuptools import setup, find_packages

setup(
    packages=find_packages(),
    package_data={'quantum_sniffer': ['py.typed']},
    include_package_data=True,
)
