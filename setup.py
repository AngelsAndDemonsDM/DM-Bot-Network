from pathlib import Path

from setuptools import find_packages, setup


def read_version():
    init_file = Path("DMBotNetwork") / "version.py"
    with init_file.open("r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]

    raise RuntimeError("Не удалось прочитать версию.")


long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="DMBotNetwork",
    version=read_version(),
    packages=find_packages(),
    install_requires=["aiosqlite", "aiohttp", "aiofiles", "bcrypt", "msgpack"],
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
