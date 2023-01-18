ARG BUILDPLATFORM="linux/arm64"
ARG BUILDERIMAGE="golang:1.19"
ARG BASEIMAGE="gcr.io/distroless/static:nonroot"

FROM --platform=$BUILDPLATFORM $BUILDERIMAGE as builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
ARG LDFLAGS

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/sigstore/cosign-gatekeeper-provider

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o provider provider.go

FROM $BASEIMAGE

WORKDIR /

COPY --from=builder /go/src/github.com/sigstore/cosign-gatekeeper-provider .

USER 65532:65532

ENTRYPOINT ["/provider"]
