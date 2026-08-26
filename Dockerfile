FROM golang:1.26.7 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make

FROM ubuntu:noble-20251013 AS base

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/bin/dash-proxy /usr/local/bin/

EXPOSE 80 443

# ubuntu:noble already ships a uid-1000 `ubuntu` user, so this lands on uid 1001
# under either name. That is what lets the gem copy the old kamal-proxy-config
# volume into dash-proxy-config with `cp -a` and no chown: the owning uid is
# unchanged by the rename.
RUN useradd dash-proxy \
    && mkdir -p /home/dash-proxy/.config/dash-proxy \
    && chown -R dash-proxy:dash-proxy /home/dash-proxy

USER dash-proxy:dash-proxy

CMD ["dash-proxy", "run"]
