FROM golang:1.16-alpine as builder

# Set the Current Working Directory inside the container
WORKDIR /builder

# We want to populate the module cache based on the go.{mod,sum} files.
COPY ../go.mod .
COPY ../go.sum .

RUN go mod download

COPY .. .
RUN go build -o ca.bin ./ca

FROM alpine:3
COPY --from=builder /builder/ca.bin .
COPY ../ca_key .
CMD ./ca.bin
