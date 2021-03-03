# Helper for building Docker image locally for testing.

all:

build:
	DOCKER_BUILDKIT=1 docker build -t spicy-plugin-ci:latest .

run:
	docker run -v $$(cd .. && pwd):/opt/spicy-plugin -w /opt/spicy-plugin --cap-add SYS_PTRACE --security-opt seccomp=unconfined -i -t spicy-plugin-ci:latest /bin/bash
