import asyncio
import json
import logging
import time
import uuid

import aio_pika

from tsdfileapi.exc import ExchangeNotDeclaredError

logger = logging.getLogger(__name__)


class AmqpClient:
    def __init__(self, config: dict, exchanges: dict) -> None:
        self.config = config
        self.exchanges = exchanges
        self.connection: aio_pika.abc.AbstractRobustConnection | None = None
        self.channel: aio_pika.abc.AbstractRobustChannel | None = None
        self._exchanges: dict[str, aio_pika.abc.AbstractRobustExchange] = {}
        self._connect_lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._connect_lock:
            if self.connection and not self.connection.is_closed:
                return
            amqps = bool(self.config.get("amqps"))
            kwargs = {
                "host": self.config.get("host"),
                "port": 5671 if amqps else 5672,
                "login": self.config.get("user"),
                "password": self.config.get("pw"),
                "virtualhost": self.config.get("vhost"),
                "ssl": amqps,
            }
            if self.config.get("heartbeat") is not None:
                kwargs["heartbeat"] = self.config["heartbeat"]
            self.connection = await aio_pika.connect_robust(**kwargs)
            self.channel = await self.connection.channel()
            for backend, config in self.exchanges.items():
                ex_name = config.get("exchange")
                ex = await self.channel.declare_exchange(
                    ex_name, aio_pika.ExchangeType.TOPIC, durable=True
                )
                self._exchanges[ex_name] = ex
                logger.info(f"rabbitmq exchange: {ex_name} declared")

    async def publish_message(
        self,
        *,
        exchange: str,
        routing_key: str,
        method: str,
        uri: str,
        version: str,
        data: dict,
        persistent: bool = True,
        timestamp: int | None = None,
    ) -> None:
        """
        Publish a message to an exchange.

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
        timestamp: int, defaults to current time

        """
        payload = json.dumps(
            {"method": method, "uri": uri, "version": version, "data": data}
        )
        message = aio_pika.Message(
            body=payload.encode(),
            content_type="application/json",
            delivery_mode=(
                aio_pika.DeliveryMode.PERSISTENT
                if persistent
                else aio_pika.DeliveryMode.NOT_PERSISTENT
            ),
            timestamp=timestamp if timestamp is not None else int(time.time()),
            message_id=str(uuid.uuid4()),
        )
        try:
            ex = self._exchanges[exchange]
        except KeyError:
            raise ExchangeNotDeclaredError(exchange, list(self._exchanges))
        await ex.publish(message, routing_key=routing_key)

    async def close(self) -> None:
        if self.connection and not self.connection.is_closed:
            await self.connection.close()
            logger.info("rabbitmq connection closed")
