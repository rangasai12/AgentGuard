from importlib.metadata import PackageNotFoundError, version

from .client import DaemonClient, DaemonUnavailable, default_socket_path
from .exceptions import DaemonPolicyMismatch, PolicyDenied
from .guard import DaemonStartError, Guard

try:
    __version__ = version("agentguard")
except PackageNotFoundError:
    # Not installed (e.g. running straight from a checkout without
    # `pip install -e .`) — pyproject.toml stays the single source of
    # truth for the real version; this is just a placeholder so
    # `agentguard.__version__` never raises.
    __version__ = "0.0.0-dev"

__all__ = [
    "Guard",
    "PolicyDenied",
    "DaemonStartError",
    "DaemonPolicyMismatch",
    "DaemonClient",
    "DaemonUnavailable",
    "default_socket_path",
    "__version__",
]
