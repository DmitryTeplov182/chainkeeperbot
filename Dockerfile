# Use the official Golang image for building the application
FROM golang:1.22.3-alpine as builder

# Set the current working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -o chainkeeper-bot main.go

# Use a smaller base image for the final image
FROM alpine:latest

# Create a non-root user and group
RUN addgroup -S chainkeeper && adduser -S chainkeeper -G chainkeeper

# Set the working directory
WORKDIR /home/chainkeeper/

# Copy the built binary from the builder stage
COPY --from=builder /app/chainkeeper-bot .

# Copy HTML files
COPY --from=builder /app/html /home/chainkeeper/html

# Change ownership of the files to the non-root user
RUN chown -R chainkeeper:chainkeeper /home/chainkeeper/

# Switch to the non-root user
USER chainkeeper

# Expose the port the app runs on
EXPOSE 8080

# Command to run the executable
CMD ["./chainkeeper-bot"]