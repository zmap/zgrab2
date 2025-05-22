## Build image ##
ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-alpine3.21 AS build

# System dependencies
RUN apk add --no-cache make

WORKDIR /usr/src/zgrab2

# Copy and cache deps
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build the actual app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux make all

## Runtime image ##
FROM alpine:latest

COPY --from=build /usr/src/zgrab2/cmd/zgrab2/zgrab2 /usr/bin/zgrab2
RUN mkdir -p /root/.config/zgrab2
COPY --from=build /usr/src/zgrab2/conf/blocklist.conf /root/.config/zgrab2/blocklist.conf

WORKDIR /usr/bin/
ENTRYPOINT ["zgrab2"]
