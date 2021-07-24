FROM node:15-alpine3.13 as builder

WORKDIR /builder
COPY ./ui/package.json .
COPY ./ui/yarn.lock .
RUN yarn
COPY ./ui .

RUN yarn build

FROM caddy:2.3.0-alpine
COPY ./gateway/Caddyfile /etc/caddy/Caddyfile
COPY --from=builder /builder/dist /srv/
