FROM golang:1.8

WORKDIR /go/src/github.com/zmap

# Grab the currently-active version of the source
ADD . zgrab2

# This would instead grab it from the source repo
# RUN go-wrapper download github.com/zmap/zgrab2

WORKDIR /go/src/github.com/zmap/zgrab2

RUN go get ./...
RUN go get -t ./...

# This should already be executable, but just in case...
RUN chmod a+x ./docker-runner/runner.sh

# Build on the container
RUN cd cmd/zgrab2 && go build && cd ../..

CMD []
ENTRYPOINT ["/go/src/github.com/zmap/zgrab2/docker-runner/runner.sh"]
