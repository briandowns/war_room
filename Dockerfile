FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    clang \
    libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/briandowns/librattler && \
    cd librattler && \
    make && make install && \
    ldconfig

COPY . /app

RUN make

COPY bin/war_room /usr/bin/war_room

ENTRYPOINT ["/usr/bin/war_room"]
