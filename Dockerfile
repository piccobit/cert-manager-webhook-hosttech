FROM golang:1.19-alpine AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

RUN go install github.com/go-delve/delve/cmd/dlv@latest

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .
RUN CGO_ENABLED=0 go build -o webhook.debug -gcflags="all=-N -l" -ldflags '-extldflags "-static"' .

FROM alpine:3.9

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/webhook* /usr/local/bin

EXPOSE 40000

CMD ["webhook"]
