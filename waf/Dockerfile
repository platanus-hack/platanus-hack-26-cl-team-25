# Coraza + OWASP CRS detection service. Builds a static-ish binary and ships it on a small base.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN go get github.com/corazawaf/coraza/v3 \
    github.com/corazawaf/coraza-coreruleset/crs/v4 \
    github.com/corazawaf/coraza-coreruleset/coraza/v3 \
    github.com/jcchavezs/mergefs \
 && go mod tidy \
 && go build -o /waf .

FROM alpine:3.20
COPY --from=build /waf /waf
EXPOSE 8080
ENTRYPOINT ["/waf"]
