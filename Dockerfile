FROM golang:alpine3.16
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN apk add build-base && go mod download
COPY *.go ./
RUN go build -o /binary

FROM alpine
COPY --from=0 /binary /usr/local/bin/bug-checker
CMD ["/usr/local/bin/bug-checker"]
