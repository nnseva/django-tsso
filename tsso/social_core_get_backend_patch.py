"""
The patch for the deprecated social_core.strategy.BaseStrategy
"""
import logging

from social_core.strategy import BaseStrategy
from social_core.backends.utils import get_backend

logger = logging.getLogger(__name__)


class BaseStrategyPatch:
    def get_backend_class(self, name):
        """Return a configured backend class"""
        return get_backend(self.get_backends(), name)

    def get_backend(self, name, redirect_uri=None, *args, **kwargs):
        """Return a configured backend instance"""
        Backend = self.get_backend_class(name)
        return Backend(self, redirect_uri=redirect_uri, *args, **kwargs)


def patch():
    if hasattr(BaseStrategy, 'get_backend'):
        return
    logger.info('Patching BaseStrategy')
    BaseStrategy.get_backend_class = BaseStrategyPatch.get_backend_class
    BaseStrategy.get_backend = BaseStrategyPatch.get_backend
