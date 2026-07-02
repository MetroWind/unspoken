FROM hexpm/elixir:1.15.4-erlang-26.0.2-alpine-3.18.2

ENV ERL_EPMD_ADDRESS=127.0.0.1
ENV MIX_ENV=prod

ARG AKKOMA_REF=stable
ARG HOME=/opt/akkoma
ARG UNAME=akkoma
ARG UID=1000
ARG GID=1000

RUN apk add --no-cache \
        cmake \
        exiftool \
        ffmpeg \
        file-dev \
        g++ \
        gcc \
        git \
        imagemagick \
        libmagic \
        make \
        musl-dev \
        ncurses \
        postgresql-client

RUN addgroup -g "$GID" "$UNAME" \
    && adduser -u "$UID" -G "$UNAME" -D -h "$HOME" "$UNAME"

WORKDIR /opt/akkoma

RUN git clone --branch "$AKKOMA_REF" --depth 1 \
        https://akkoma.dev/AkkomaGang/akkoma.git /opt/akkoma \
    && chown -R "$UNAME:$UNAME" /opt/akkoma

USER akkoma

RUN mix local.hex --force \
    && mix local.rebar --force \
    && mix deps.get --only prod \
    && mix compile

USER root

COPY interop-entrypoint.sh /opt/interop/interop-entrypoint.sh
COPY interop_blob.png.b64 /opt/interop/interop_blob.png.b64
RUN chown -R "$UNAME:$UNAME" /opt/interop \
    && chmod 0755 /opt/interop/interop-entrypoint.sh

USER akkoma

EXPOSE 4000

CMD ["/opt/interop/interop-entrypoint.sh"]
