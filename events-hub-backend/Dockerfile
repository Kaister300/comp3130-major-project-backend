# Base image
FROM python:3.12-slim-bookworm

# App Name
ENV APP_NAME=events-hub-backend

# Copy Files Over
COPY $APP_NAME/ /app

# Create Workdir
WORKDIR /app

# Install Dependencies
RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

# Expose Port
EXPOSE 3000

# Run App
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000", "--interface", "wsgi"]