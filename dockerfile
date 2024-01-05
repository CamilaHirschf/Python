FROM python:latest
RUN chmod -R 755 /app
COPY requirements.txt /
RUN pip3 install --upgrade pip
RUN pip3 install -r /requirements.txt
COPY . /app
WORKDIR /app
EXPOSE 8080




CMD ["gunicorn","--config", "gunicorn_config.py", "app:create_app()"]
