FROM golang:1.24-alpine AS build
WORKDIR /app
RUN apk add --no-cache build-base sqlite-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /minitwit .

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates sqlite-libs curl
COPY --from=build /minitwit /app/minitwit
COPY templates /app/templates
COPY static /app/static
COPY schema.sql /app/schema.sql
EXPOSE 5000
CMD ["/app/minitwit"]
