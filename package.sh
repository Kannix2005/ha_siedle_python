#!/bin/sh
rm dist/*
python setup.py sdist
python setup.py bdist_wheel
python -m twine upload dist/* --verbose
pip install ha_siedle_python --upgrade