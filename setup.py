from setuptools import setup, find_packages

setup(
    name='check_redfish',
    version='2.0.0',
    author='bb-Ricardo',
    author_email='ricardo@bitchbrothers.com',
    description='A monitoring/inventory plugin to check components and health status of systems which support Redfish.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/bb-Ricardo/check_redfish',
    packages=find_packages(),
    install_requires=[
        'redfish>=2.1.4',
    ],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        "Environment :: Console",
        'Programming Language :: Python :: 3',
        "Topic :: System :: Monitoring",
    ],
    python_requires='>=3.6',
    py_modules=["check_redfish"],
    entry_points={
        'console_scripts': [
            'check_redfish=check_redfish:main',
        ],
    },
)
