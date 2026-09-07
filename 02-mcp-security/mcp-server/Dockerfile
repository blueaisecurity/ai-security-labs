FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vuln_mcp_server.py .
CMD ["python", "vuln_mcp_server.py"]
