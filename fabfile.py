from fabric.api import local

# Automate the release
def release():
    local("python setup.py sdist register upload")
    local("python2.5 setup.py bdist_egg register upload")
    local("python2.6 setup.py bdist_egg register upload")
    local("python2.7 setup.py bdist_egg register upload")