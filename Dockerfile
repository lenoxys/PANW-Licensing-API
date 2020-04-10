FROM python:3.6-slim as base

COPY requirements.txt /tmp/

RUN pip3 install -r /tmp/requirements.txt

RUN useradd --create-home panlic
WORKDIR /home/panlic
USER panlic

COPY app/ app/

WORKDIR app

CMD ["python3", "./watch.py", "-d"]
