FROM golang:1.13.10-alpine
WORKDIR /go/src/github.com/SD-Paranoia/ufo
ADD . ./
RUN go install github.com/SD-Paranoia/ufo/cmd/ufo
ENTRYPOINT ["/go/bin/ufo"]
