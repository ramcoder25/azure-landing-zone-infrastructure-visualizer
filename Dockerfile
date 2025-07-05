FROM python:3.9-slim
WORKDIR /landing-zone
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "landing-zone.py"]
