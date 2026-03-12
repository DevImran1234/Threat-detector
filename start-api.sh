#!/bin/bash
# Start the API Server for MITRE Security Pipeline

echo "🚀 Starting MITRE Security Pipeline API Server..."
echo "API will be available at http://localhost:8000"
echo "API Documentation at http://localhost:8000/docs"
echo ""

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Install dependencies if needed
echo "Checking dependencies..."
pip install -q -r requirements.txt

# Start the API server
echo "Starting API server..."
python -m uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload

echo "API Server stopped"
