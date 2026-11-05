# ---- Build stage -------------------------------------------------------
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

COPY src ./src
RUN mkdir -p out \
    && javac --release 11 -d out src/Main.java

# ---- Runtime stage -----------------------------------------------------
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app

COPY --from=build /app/out ./out
COPY public ./public

ENV PORT=8080
EXPOSE 8080

# The container must bind to all interfaces so the platform can route traffic.
CMD ["java", "--add-modules", "jdk.httpserver", "-cp", "out", "Main", "--host", "0.0.0.0"]
