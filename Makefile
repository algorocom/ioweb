.PHONY: all flake flake_verbose test coverage clean upload

flake:
	flake8 crawler test script

flake_verbose:
	flake8 crawler test script --show-pep8

test:
	pytest --cov-report term-missing --cov crawler

coverage:
	coverage erase
	coverage run --source=crawler -m runscript.cli test
	coverage report -m

clean:
	find -name '*.pyc' -delete
	find -name '*.swp' -delete

release:
	git push; git push --tags; python setup.py clean sdist upload
