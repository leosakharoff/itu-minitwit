FROM golang:1.24-alpine
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o minitwit .
EXPOSE 5000
CMD ["./minitwit"]
