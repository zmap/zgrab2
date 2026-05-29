FROM golang:1.23 AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o server main.go

FROM debian:stable-slim
WORKDIR /app
COPY --from=build /app/server .
EXPOSE 8083
CMD ["./server"]
