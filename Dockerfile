# syntax=docker/dockerfile:1
FROM python:3.9-slim-buster
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -U pip && pip3 install -r requirements.txt --no-cache-dir && pip3 install redis
EXPOSE 5000
COPY . .
RUN export FLASK_ENV=development
CMD ["python3", "app.py"]