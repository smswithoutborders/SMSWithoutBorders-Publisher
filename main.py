#!/usr/bin/env python3

import pika

credentials=pika.PlainCredentials("sherlock", "asshole")
connection = pika.BlockingConnection(pika.ConnectionParameters(
            host='staging.smswithoutborders.com',
            credentials=credentials))

channel = connection.channel()

result = channel.queue_declare(queue='unofficial-smswithoutborders-queue', 
                               durable=True)

queue_name = result.method.queue

channel.queue_bind(exchange='smswithoutborders-exchange', 
                   queue=queue_name, 
                   routing_key="smswithoutborders-default-routing-key")

print(' [*] Waiting for logs. To exit press CTRL+C')

def callback(ch, method, properties, body):
    print(" [x] %r" % body)

channel.basic_consume(
        queue=queue_name, 
        on_message_callback=callback, 
        auto_ack=True)

channel.start_consuming()
