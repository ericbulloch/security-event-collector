from abc import ABC, abstractmethod
from typing import Optional

import src.config as config


class BaseParser(ABC):
    @property
    def source(self) -> str:
        return config.SOURCE

    @abstractmethod
    def parse(self, line: str) -> Optional[dict]:
        pass
