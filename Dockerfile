FROM python:3.6-alpine as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt
FROM base
COPY --from=builder /install /usr
COPY app/ app/
WORKDIR /app
CMD ["./watch.py", "-d"]