
import json
import logging

import pika

from pika.adapters.tornado_connection import TornadoConnection


class PikaClient(object):

    def __init__(self, config, exchanges):
        self.connecting = False
        self.connection = None
        self.channel = None
        self.config = config
        self.exchanges = exchanges

    def connect(self):
        if self.connecting:
            return
        self.connecting = True
        creds = pika.PlainCredentials(
            self.config.get('user'),
            self.config.get('pw')
        )
        params = pika.ConnectionParameters(
            host=self.config.get('host'),
            port=5671 if self.config.get('amqps') else 5672,
            virtual_host=self.config.get('vhost'),
            credentials=creds
        )
        self.connection = TornadoConnection(params)
        self.connection.add_on_open_callback(self.on_connect)
        self.connection.add_on_close_callback(self.on_closed)
        return

    def on_connect(self, connection):
        self.connection = connection
        self.channel = self.connection.channel(
            on_open_callback=self.on_channel_open
        )
        return

    def on_channel_open(self, channel):
        for backend, config in self.exchanges.items():
            ex_name = config.get('exchange')
            channel.exchange_declare(
                ex_name,
                exchange_type='topic',
                durable=True
            )
            logging.info(f'rabbitmq exchange: {ex_name} declared')
        return

    def on_basic_cancel(self, frame):
        self.connection.close()

    def on_closed(self, connection):
        tornado.ioloop.IOLoop.instance().stop()

    def publish_message(
            self,
            exchange=None,
            routing_key=None,
            method=None,
            uri=None,
            version=None,
            data=None,
            persistent=True
        ):
        """
        Publilsh a message to an exchange.

        Parameters
        ----------
        exchange: str, exchange name
        routing_key: str, routing key for topic exchange
        method: str, HTTP method
        uri: str, HTTP request URI
        version: str, e.g. v1
        data: dict
        persistent: bool, default True
            tell rabbitmq to persist messages to disk, or not

        """
        data = {
            'method': method,
            'uri': uri,
            'version': version,
            'data': data
        }
        message = json.dumps(data)
        delivery_mode = 2 if persistent else 1
        self.channel.basic_publish(
            exchange=exchange,
            routing_key=routing_key,
            body=message,
            properties=pika.BasicProperties(
                content_type='application/json',
                delivery_mode=delivery_mode
            )
        )
        return
