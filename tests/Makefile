
all: test
test: test-build

test-build:
	@btest -d -j "$${SPICY_ZKG_PROCESSES:-4}"

test-install:
	@btest -d -a installation -j "$${SPICY_ZKG_PROCESSES:-4}"

clean:
	@rm -f $(DIAG) .btest.failed.dat
	@rm -rf .tmp

.PHONY: all test-build clean
