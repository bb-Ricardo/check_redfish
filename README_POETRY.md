# Documentation for poetry
This is how packaging could work, it is not a complete documentation but a starting point for you.
Do what you want with this file, my intention was to make as less changes as possible to your code and
prevent braking changes.
The script can still be called on commandline like before after checking out from git, but now it
can also be installed as a pip package and can be imported.
When installed as pip package an os command will be installed in system path at ```/usr/local/bin/check_redfish```
or when using an virtual environment in your virtual environment.

From now there are 3 possibilities to call the script,

When you are in the root directory of the git repository:

```bash
python -m checkredfish
./check_redfish.py
```

From everywhere on your filesystem by calling the following command, the ```PATH``` variable must be set right:

```bash
check_redfish
```


## Create requirements.txt file from pyproject.toml file
```bash
poetry export -f requirements.txt --output requirements.txt
```

## install current package
```bash
poetry install
  --no-root         # do not install the root package (current project)
  --only-root       # dependencies nicht installieren
  --with dev        # dev dependencies installieren ([tool.poetry.group.dev.dependencies])
  --dry-run         # no changes
```

## remove the installed package
This must be done using pip

```bash
pip3 uninstall check-redfish
```


## build a package from current project
```bash
poetry build
pip3 install ./dist/check_redfish-<version>.tar.gz
```

## Publish to [pypi](https://pypi.org)
First create account and create a token on [pypi](https://pypi.org)
After this run following commands, replace ```<your-api-token>``` with the token received from [pypi](https://pypi.org)

```bash
poetry config pypi-token.pypi <your-api-token>
poetry build
poetry publish
```
