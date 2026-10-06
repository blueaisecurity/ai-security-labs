FROM python:3.11.16-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir --no-deps llamafirewall==1.0.3
COPY judges.py .
CMD ["python", "-u", "judges.py"]
