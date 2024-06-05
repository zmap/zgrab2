## Build image ##
FROM golang:1.20.4-alpine3.16 as build

# System dependencies
RUN apk add --no-cache make

WORKDIR /usr/src/zgrab2

# Copy and cache deps
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build the actual app
COPY . .
RUN make all

## Runtime image ##
FROM alpine:3.20 as run

COPY --from=build /usr/src/zgrab2/cmd/zgrab2/zgrab2 /usr/bin/zgrab2

ENTRYPOINT ["/usr/bin/zgrab2"]
