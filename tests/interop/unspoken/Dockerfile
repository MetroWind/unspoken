FROM archlinux:base

WORKDIR /app

RUN pacman -Sy --needed --noconfirm \
        ca-certificates \
        curl \
        gcc-libs \
        icu \
        openssl \
        sqlite \
    && pacman -Scc --noconfirm < /dev/null

RUN mkdir -p /app/data

COPY build/unspoken /usr/local/bin/unspoken
COPY build/data/emoji_categories.json /app/data/emoji_categories.json
COPY templates /app/templates
COPY static /app/static

RUN mkdir -p /data/attachments /data/emoji \
    && chmod 0755 /usr/local/bin/unspoken

EXPOSE 8080

CMD ["/usr/local/bin/unspoken", "--config", "/config/unspoken.yaml"]
