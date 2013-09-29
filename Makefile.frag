clean-coverage:
	-rm -rf .coverage coverage

coverage: test clean-coverage
	$(LCOV) --directory . --capture --base-directory=. --output-file .coverage
	$(GENHTML) --legend --output-directory coverage/ --title "Code Coverage" .coverage
