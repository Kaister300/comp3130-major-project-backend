# Base image
FROM python:3.12-slim-bookworm

# App Name
ENV APP_NAME=events-hub-backend

# Set Workdir
WORKDIR /app

# Copy Requirements Over
COPY $APP_NAME/requirements.txt /app/requirements.txt

# Install Dependencies
RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

# Copy files over
COPY $APP_NAME/templates/ /app/templates/
COPY $APP_NAME/static/ /app/static/
COPY $APP_NAME/models.py /app/models.py
COPY $APP_NAME/app.py /app/app.py
COPY $APP_NAME/json_validation_schemas.py /app/json_validation_schemas.py

# Expose Port
EXPOSE 3000

# Run App
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000", "--interface", "wsgi"]