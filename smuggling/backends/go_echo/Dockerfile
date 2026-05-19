FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o go-echo main.go

FROM alpine:3.19
COPY --from=builder /app/go-echo /usr/local/bin/go-echo
EXPOSE 8889
CMD ["go-echo"]
