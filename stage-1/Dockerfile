FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /pocketful .

FROM scratch
COPY --from=build /pocketful /pocketful
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/pocketful"]
