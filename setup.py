from setuptools import setup, find_packages

setup(
	name="skoolkit_controlfile_generator",
	version="0.5.0",
	packages=find_packages(),
	install_requires=[
		'num2words',
	],
	author="Paul Maddern",
	author_email="paul@arcadegeek.co.uk",
	description="Generates a stub Skoolkit control file for the game in the current directory.",
	long_description=open("README.md").read(),
	long_description_content_type="text/markdown",
	url="https://github.com/pobtastic/skoolkit_controlfile_generator",
	entry_points={
		'console_scripts': [
			'disassemble=generator.cli:main',
		],
	},
	classifiers=[
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
		"Operating System :: OS Independent",
	],
)
