from __future__ import annotations
from abc import ABC, abstractmethod


class ServiceHandler(ABC):
    """Parent class for handlers of interaction with external services"""

    def __init__(self, key) -> None:
        self._key = key

    @staticmethod
    async def _fetch(session, url, params=None):
        async with session.get(url, params=params) as response:
            return await response.json()

    @abstractmethod
    async def get_ip_data(self, address):
        """Get IP data for indicator from service"""
