# unwired-server

Welcome to unwired-server! This is the backend for the android app Unwired.

## Installation

### With Docker (recommended)

1. Make sure you have Docker installed on your system.
2. Clone the repository: `git clone https://github.com/harmdhast/unwired-server.git`
3. Navigate to the project directory: `cd unwired-server`
4. Run the Docker stack: `docker compose up -d`

### Without Docker

1. Make sure you have Python 3.12 or higher and a PostgreSQL server installed on your system.
2. Clone the repository: `git clone https://github.com/harmdhast/unwired-server.git`
3. Navigate to the project directory: `cd unwired-server`
4. Create a virtual environment: `python3 -m venv venv`
5. Activate the virtual environment:
    - On macOS and Linux: `source venv/bin/activate`
    - On Windows: `venv\Scripts\activate.bat`
6. Install the building deps : `RUN apt-get update && apt-get -y install libpq-dev gcc`
7. Install the required dependencies: `pip install -r requirements.txt`
8. Edit the `DB_URL` variable to match your database setup.
7. Start the server: `uvicorn run:app --host 0.0.0.0 --port 8000`

## Usage

Once the server is running, you can access the Swagger API at `http://localhost:8000/docs`.