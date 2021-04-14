FROM golang:1.16
# Base image that already has the pre-requisites downloaded.

WORKDIR /go/src/github.com/zmap/zgrab2

RUN go get -v ./...
RUN go get -v -t ./...
