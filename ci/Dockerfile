FROM debian:bullseye-slim AS build

RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
    bind9 \
    bison \
    ccache \
    clang-tidy-13 \
    cmake \
    curl \
    flex \
    g++ \
    gcc \
    git \
    jq \
    libfl-dev \
    libfl2 \
    libmaxminddb-dev \
    libpcap-dev \
    libssl-dev \
    libz-dev \
    make \
    ninja-build \
    python3-git \
    python3-minimal \
    python3-minimal \
    python3-pip \
    python3-semantic-version \
    python3-websocket \
    python3.9-dev \
    swig \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/run-clang-tidy run-clang-tidy /usr/lib/llvm-13/bin/run-clang-tidy 20

ARG ZEEK_VERSION="v5.0.4"
RUN git clone -b $ZEEK_VERSION --depth=1 https://github.com/zeek/zeek /src/zeek

ARG ZEEK_CONFFLAGS="--disable-spicy"
RUN cd /src/zeek \
 && git submodule update --init --recursive --depth=1 \
 && ./configure --generator=Ninja $ZEEK_CONFFLAGS \
 && ninja -C build install \
 && cd - \
 && rm -rf /src/zeek
ENV PATH="/opt/spicy/bin:/usr/local/zeek/bin:${PATH}"

WORKDIR /
