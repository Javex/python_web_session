

class PySessException(Exception):
    """Base exception for all pyess exceptions to inherit from"""


class SessionConfigurationError(PySessException):
    """The sessionmaker session was already configured."""


class CryptoError(PySessException):
    """There was an error concerning a cryptographic operation."""