
test:
	python tests/test_jwt.py

release:
	python setup.py sdist register upload
	python2.6 setup.py bdist_egg register upload
	python2.7 setup.py bdist_egg register upload
	python3 setup.py bdist_egg register upload
