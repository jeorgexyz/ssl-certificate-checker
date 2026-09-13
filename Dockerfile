# Build stage: compile the escript. Keep the OTP major version in step with the runtime image.
FROM elixir:1.14.5-otp-25-alpine AS build

WORKDIR /app
ENV MIX_ENV=prod

RUN mix local.hex --force && mix local.rebar --force

COPY mix.exs mix.lock ./
COPY config ./config
RUN mix deps.get --only prod && mix deps.compile

COPY lib ./lib
RUN mix escript.build

# Runtime stage: the escript bundles Elixir and its dependencies, so only Erlang is needed.
FROM erlang:25-alpine

RUN apk add --no-cache ca-certificates

COPY --from=build /app/ssl_certificate_checker /usr/local/bin/ssl_certificate_checker

USER nobody
ENTRYPOINT ["ssl_certificate_checker"]
CMD ["--help"]

# Build: docker build -t ssl-certificate-checker .
# Run:   docker run --rm ssl-certificate-checker google.com --json
