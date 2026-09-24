# ARGUS Project Setup Instructions

To run this project on another machine, you will need to set up both the backend (Python API) and the frontend (React app), along with the necessary background services (PostgreSQL and MinIO).

## Prerequisites
Make sure the new machine has the following installed:
- **Python 3.10+**
- **Node.js** (v18 or higher recommended)
- **PostgreSQL** (for the database)
- **MinIO** (for evidence storage)

---

## 1. Database & Services Setup
1. Create a PostgreSQL database (e.g., named `argus_db`).
2. Set up a MinIO bucket for evidence uploads.
3. In the root of the project, create an `.env` file (you can copy `.env.example` if it exists) and fill in your local Postgres and MinIO credentials.

## 2. Backend Setup (FastAPI)
Open a terminal in the root directory of the project (`argus/`) and run the following commands:

```bash
# 1. Create a virtual environment
python -m venv venv

# 2. Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 3. Install backend dependencies
pip install -r requirements.txt

# 4. Run the database seed/initialization scripts if necessary
# (e.g., importing seed/postgres_init.sql into your database)

# 5. Start the backend server
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API will now be running on `http://127.0.0.1:8000`.

---

## 3. Frontend Setup (React / Vite)
Open a **new** terminal window, navigate to the frontend folder, and start the app:

```bash
# 1. Navigate to the frontend directory
cd sample/FE

# 2. Install Node dependencies
npm install

# 3. Start the development server
npm run dev
```
The frontend will start up and provide you with a localhost URL (usually `http://localhost:5173`). Open this URL in your browser to access the application.
