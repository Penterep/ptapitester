import setuptools

with open("ptapitester/_version.py") as f:
    __version__ = f.readline().split('"')[1]

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ptapitester",
    description="API penetration testing tool (Penterep tool)",
    version=__version__,
    author="Penterep",
    author_email="vit.stankus@gmail.com",
    url="https://www.penterep.com/",
    license="GPLv3+",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    python_requires=">=3.12",
    install_requires = [
        "ptlibs>=1.0.25",
        "ptthreads"
],
    entry_points={"console_scripts": ["ptapitester = ptapitester.ptapitester:main"]},
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
    project_urls = {
        "homepage": "https://www.penterep.com/",
        "repository": "https://github.com/Penterep/ptapitester",
        "tracker": "https://github.com/Penterep/ptapitester/issues"
    }
)
