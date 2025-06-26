from fastapi import FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from parser import SecurityLogParser
from calculator import SecurityKPICalculator

# Add a test route to verify the API is working
@app.get("/")
async def test_api():
    return {"message": "API is working correctly"}

# it should take a file as input
# and return the parsed logs and calculated KPIs
@app.post("/file_upload/")
async def file_upload(file: UploadFile = File(...)):
    """
    Endpoint to handle file uploads for security logs.
    """
    try:
        content = await file.read()
        log_lines = content.decode('utf-8').splitlines()

        # Initialize parser and calculator
        parser = SecurityLogParser()
        calculator = SecurityKPICalculator()

        # Parse logs
        parsed_logs = []
        for line in log_lines:
            print(line,"\n\n")  # Debugging line to check each log line
            parsed = parser.parse_log(line)
            if parsed:
                parsed_logs.append(parsed)

        # Calculate KPIs
        calculator.add_logs(parsed_logs)

        strategic_kpis = calculator.calculate_strategic_kpis()
        managerial_kpis = calculator.calculate_managerial_kpis()
        operational_kpis = calculator.calculate_operational_kpis()

        return {
            "strategic_kpis": strategic_kpis,
            "managerial_kpis": managerial_kpis,
            "operational_kpis": operational_kpis
        }

    except Exception as e:
        return {"error": str(e)}
   

@app.get("/health")
async def health_check():
    """
    Health check endpoint to verify the API is running.
    """
    return {"status": "healthy"}