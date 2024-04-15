# COMP3130 Major Project Backend
Python Flask server to handle requests from mobile application to the "Events Hub" web service.

# Installation - Local
First, download Python 3.12. Then, initialise a python environment using `py -m venv ./venv`. After, run `py -m pip install -r ./events-hub-backend/requirements.txt` while inside the environment.

The project can be started using `py ./events-hub-backend/app.py`. It will start a web service that runs on the `3000` port on the localhost interface. The interface and ports can be changed by setting the following environment variables, `HOSTNAME` and `PORT`.

In order to use the whole server, you will need to create a SightEngine account so that content scanning is available. You can disable content scanning but only for the Admin through the `ENABLE_UNSAFE_ADMIN` environment variable.

# Installation - Docker
A Docker Compose file has been included to build and deploy the project through Dockers. In order to use this, ensure that you have the Docker Engine downloaded on your respective operating system. Then ensure that the `.env.example` file it filled out and renamed to `.env`.
From here, you can then add your SSL certificate to the `./nginx/ssl` folder. The server only runs over a HTTPS connection so if you want to change that, you'll need to edit `nginx.conf`.
Finally, run the following commands:
```bash
docker compose build events-hub-backend
docker compose up events-hub-backend nginx
```

The backend flask server will always run on port `3000` in the local Docker network, this should not be changed through passing environment variables.