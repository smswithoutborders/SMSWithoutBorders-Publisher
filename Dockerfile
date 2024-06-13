FROM python:3.9

RUN apt-get update && \
    apt-get install -y build-essential \
    apache2 apache2-dev \
    python3-dev \
    supervisor && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /publisher

COPY . .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN pip install -U pip && \
    pip install --no-cache-dir wheel && \
    pip install --no-cache-dir --force-reinstall -r requirements.txt

ENV MODE=production
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]