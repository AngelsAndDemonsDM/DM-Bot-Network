from setuptools import find_packages, setup

setup(
    name="DMBotNetwork",
    version="0.2.0",
    packages=find_packages(),
    install_requires=["aiosqlite", "aiofiles", "bcrypt", "msgpack"],
    author="Angels And Demons dev team",
    author_email="dm.bot.adm@gmail.com",
    description="Нэткод для проектов DMBot",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/AngelsAndDemonsDM/DM-Bot-network",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    license="GPL-3.0",
)
