FROM archlinux:base

WORKDIR /app

RUN pacman -Sy --needed --noconfirm \
        ca-certificates \
        curl \
        gcc-libs \
        openssl \
    && pacman -Scc --noconfirm < /dev/null

COPY build/fake_oidc /usr/local/bin/fake_oidc
COPY tests/interop/fake_oidc/jwt_private.pem /app/jwt_private.pem
COPY tests/interop/fake_oidc/jwt_public.jwk /app/jwt_public.jwk

RUN chmod 0755 /usr/local/bin/fake_oidc

EXPOSE 9000

CMD ["/usr/local/bin/fake_oidc"]
