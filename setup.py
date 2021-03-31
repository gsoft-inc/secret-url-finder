from setuptools import setup, find_packages

setup(
    name='secret_url_finder',
    version='2.0.0',
    description='Tool that finds URLs for a given domain by using different sources.',
    url='https://github.com/gsoft-inc/secret-url-finder',
    author='Mathieu Gascon-Lefebvre',
    author_email='mathieuglefebvre@gmail.com',
    license='Apache',
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        'python-dateutil',
        'beautifulsoup4',
        'requests',
        'pytz'
    ],
    entry_points={
        'console_scripts': ['secret-url-finder = secret_url_finder.main:main'],
    },
)
