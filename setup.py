from setuptools import find_packages, setup

from DMBotNetwork import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="DMBotNetwork",
    version=__version__,
    packages=find_packages(),
    install_requires=["aiosqlite", "aiofiles", "bcrypt", "msgpack"],
    author="Angels And Demons dev team",
    author_email="dm.bot.adm@gmail.com",
    description="Нэткод для проектов DMBot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AngelsAndDemonsDM/DM-Bot-network",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    license="GPL-3.0",
)
