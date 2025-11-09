# Use the correct OpenJDK 21 slim image
FROM eclipse-temurin:21-jdk

# Set the working directory inside the container
WORKDIR /app

# Copy the built .jar file
# (Make sure this name is correct)
COPY target/Internal_flag_manager-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your Spring app runs on
EXPOSE 9000

# The command to run your app
CMD ["java", "-jar", "app.jar"]