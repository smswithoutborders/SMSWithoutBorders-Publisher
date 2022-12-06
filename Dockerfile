FROM python:3.9

RUN apt update && apt install -y apache2 apache2-dev python3-pip less vim

WORKDIR /publisher

COPY . .

RUN pip install --force-reinstall -r requirements.txt

CMD python main.py
