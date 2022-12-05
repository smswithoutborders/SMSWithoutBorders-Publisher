#!/usr/bin/env python3

import os
import pika
import random
from retry import retry
import logging
import base64

import aes

logging.basicConfig(level="DEBUG")

shared_key = os.environ["PUBLISHER_DECRYPTION_KEY"]

def publishing_payload(ch, method, properties, body: bytes) -> None:
    """
    """
    logging.info("Publishing payload: %s", body)

    try:
        body = base64.b64decode(body)

        iv = body[:16]
        body = body[16:]

        body = aes.AESCipher.decrypt(data=body, shared_key=shared_key, iv=iv)

    except Exception as error:
        logging.exception(error)

        ch.basic_reject(delivery_tag=method.delivery_tag, requeue=True)

    else:
        logging.info("decrypted payload: %s", body)

        ch.basic_ack(delivery_tag=method.delivery_tag)


@retry(pika.exceptions.AMQPConnectionError, delay=5, jitter=(1, 3))
def consumer():
    """
    """
    credentials=pika.PlainCredentials("sherlock", "asshole")
    connection = pika.BlockingConnection(pika.ConnectionParameters(
        heartbeat=30,
        blocked_connection_timeout=300,
        host='staging.smswithoutborders.com',
        credentials=credentials))

    channel = connection.channel()

    result = channel.queue_declare(queue='unofficial-smswithoutborders-queue', 
                                   durable=True)

    queue_name = result.method.queue

    channel.queue_bind(exchange='smswithoutborders-exchange', 
                       queue=queue_name, 
                       routing_key="smswithoutborders-default-routing-key")

    channel.basic_consume(
            queue=queue_name, 
            on_message_callback=publishing_payload)

    try:
        channel.start_consuming()
    except pika.exceptions.ConnectionClosedByBroker:
        logging.warning("Clean stoping broker...")
    except Exception as error:
        logging.exception(error)

if __name__ == "__main__":
    consumer()
