# COMP3130 Major Project Backend
Python Flask server to handle requests from mobile application to the "Events Hub" web service.

# Installation - Local
Initialise a python environment using `py -m venv ./venv`. Then run `py -m pip install -r ./events-hub-backend/requirements.txt` while inside the environment.
The project can be started using `py ./events-hub-backend/app.py`. It will start a web service that runs on the `3000` port on the localhost interface.
The interface and ports can be changed by setting the following environment variables, `HOSTNAME` and `PORT`.

# Installation - Docker
