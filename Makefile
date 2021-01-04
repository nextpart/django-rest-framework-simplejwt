.PHONY: clean
clean: clean-build clean-pyc

.PHONY: clean-build
clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info
	rm -rf $(poetry env info -p)

.PHONY: clean-pyc
clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

.PHONY: lint
lint:
	poetry run tox -e lint

.PHONY: tests
test:
	poetry run pytest tests

.PHONY: test-all
test-all:
	poetry run tox

.PHONY: build-docs
build-docs:
	poetry run sphinx-apidoc -o docs/ . \
		*confest* \
		tests/* \
		rest_framework_simplejwt/token_blacklist/* \
		rest_framework_simplejwt/backends.py \
		rest_framework_simplejwt/compat.py \
		rest_framework_simplejwt/exceptions.py \
		rest_framework_simplejwt/settings.py \
		rest_framework_simplejwt/state.py
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	$(MAKE) -C docs doctest

.PHONY: docs
docs: build-docs
	open docs/_build/html/index.html

.PHONY: linux-docs
linux-docs: build-docs
	xdg-open docs/_build/html/index.html

.PHONY: bumpversion
bumpversion:
	bumpversion $(bump)

.PHONY: pushversion
pushversion:
	git push upstream && git push upstream --tags

.PHONY: publish
publish:
	poetry build
	poetry publish

.PHONY: dist
dist: clean
	rm -rf (poetry env info -p)

