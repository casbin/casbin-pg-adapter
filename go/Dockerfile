FROM golang:1.13-alpine

RUN apk add --no-cache make git curl build-base tar

RUN git clone https://github.com/go-delve/delve.git /go/src/github.com/go-delve/delve && \
    cd /go/src/github.com/go-delve/delve && \
    make install

RUN go get golang.org/x/tools/cmd/godoc
