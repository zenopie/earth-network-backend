# Dockerfile

# 1. Use an official, lightweight Python base image
FROM python:3.11-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy the dependencies file first to leverage Docker's layer caching
COPY requirements.txt .

# 4. Install system dependencies required for packages like secp256k1
#    - build-essential: Provides C/C++ compilers (like gcc) and `make`.
#    - pkg-config: The tool the error message specifically requested.
#    - libsecp256k1-dev: The C library development files for secp256k1.
#    We chain the commands with && and clean up the apt cache to keep the image smaller.
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    git \
    libsecp256k1-dev \
    && rm -rf /var/lib/apt/lists/*

# 5. Now, install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy the rest of the application code into the container
COPY . .

# 7. Expose the port the app will run on
EXPOSE 8000

# 8. Define the command to run the application
#    --host 0.0.0.0 is crucial to make the server accessible from outside the container
#    --no-access-log disables access logging for privacy
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]