"""
User management for the delegation system.

A user has:
    - Unique identifier
    - Private key for data access (combined with delegation key)
"""

import os
from dataclasses import dataclass
from typing import Optional


# Size of user key (256 bits)
USER_KEY_SIZE = 32


@dataclass
class User:
    """
    A user in the delegation system.

    Attributes:
        user_id: Unique identifier
        key: 256-bit private key for data access
    """

    user_id: str
    key: bytes

    def __post_init__(self):
        if len(self.key) != USER_KEY_SIZE:
            raise ValueError(f"User key must be {USER_KEY_SIZE} bytes")

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format:
            - 1 byte: user_id length
            - N bytes: user_id
            - 32 bytes: key
        """
        user_bytes = self.user_id.encode("utf-8")

        result = bytearray()
        result.append(len(user_bytes))
        result.extend(user_bytes)
        result.extend(self.key)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["User", int]:
        """
        Deserialize from binary format.

        Returns:
            Tuple of (User, bytes_consumed)
        """
        offset = 0

        user_len = data[offset]
        offset += 1
        user_id = data[offset : offset + user_len].decode("utf-8")
        offset += user_len

        key = data[offset : offset + USER_KEY_SIZE]
        offset += USER_KEY_SIZE

        return cls(user_id=user_id, key=key), offset

    @classmethod
    def generate(cls, user_id: str) -> "User":
        """
        Generate a new user with random key.

        Args:
            user_id: Unique identifier

        Returns:
            New User instance
        """
        key = os.urandom(USER_KEY_SIZE)
        return cls(user_id=user_id, key=key)


class UserRegistry:
    """
    Manages the collection of users.
    """

    def __init__(self):
        self._users: dict[str, User] = {}

    def add(self, user: User) -> None:
        """Add a user to the registry."""
        if user.user_id in self._users:
            raise ValueError(f"User {user.user_id} already exists")
        self._users[user.user_id] = user

    def get(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self._users.get(user_id)

    def remove(self, user_id: str) -> None:
        """Remove a user."""
        del self._users[user_id]

    def list_all(self) -> list[User]:
        """Get all users."""
        return list(self._users.values())

    def to_bytes(self) -> bytes:
        """Serialize entire registry."""
        result = bytearray()
        result.append(len(self._users))

        for user in self._users.values():
            user_bytes = user.to_bytes()
            result.extend(len(user_bytes).to_bytes(2, "big"))
            result.extend(user_bytes)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "UserRegistry":
        """Deserialize registry."""
        registry = cls()
        offset = 0

        num_users = data[offset]
        offset += 1

        for _ in range(num_users):
            user_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2

            user, _ = User.from_bytes(data[offset : offset + user_len])
            offset += user_len

            registry._users[user.user_id] = user

        return registry
