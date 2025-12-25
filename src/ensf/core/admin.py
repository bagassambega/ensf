"""
Admin management for the delegation system.

Each admin has:
    - Unique identifier
    - Weight for coalition threshold
    - Base key for SSS participation
    - Capability keys for delegation with access rights
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from ..crypto.capability import CapabilityKeySet, CAPABILITY_KEY_SIZE
from ..crypto.aes import KEY_SIZE


# Size of admin base key (256 bits)
ADMIN_KEY_SIZE = 32


@dataclass
class Admin:
    """
    An administrator in the delegation system.

    Attributes:
        admin_id: Unique identifier (e.g., "admin1", "A1")
        weight: Voting weight for coalition threshold
        base_key: 256-bit key for SSS participation
        capability_keys: Optional set of capability keys
    """

    admin_id: str
    weight: int
    base_key: bytes
    capability_keys: Optional[CapabilityKeySet] = None

    def __post_init__(self):
        if self.weight < 1:
            raise ValueError("Weight must be at least 1")
        if len(self.base_key) != ADMIN_KEY_SIZE:
            raise ValueError(f"Base key must be {ADMIN_KEY_SIZE} bytes")

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format:
            - 1 byte: admin_id length
            - N bytes: admin_id
            - 1 byte: weight
            - 32 bytes: base_key
            - 1 byte: has_capability_keys flag
            - [optional] capability_keys data
        """
        admin_bytes = self.admin_id.encode("utf-8")

        result = bytearray()
        result.append(len(admin_bytes))
        result.extend(admin_bytes)
        result.append(self.weight)
        result.extend(self.base_key)

        if self.capability_keys:
            result.append(1)
            result.extend(self.capability_keys.to_bytes())
        else:
            result.append(0)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["Admin", int]:
        """
        Deserialize from binary format.

        Returns:
            Tuple of (Admin, bytes_consumed)
        """
        offset = 0

        admin_len = data[offset]
        offset += 1
        admin_id = data[offset : offset + admin_len].decode("utf-8")
        offset += admin_len

        weight = data[offset]
        offset += 1

        base_key = data[offset : offset + ADMIN_KEY_SIZE]
        offset += ADMIN_KEY_SIZE

        has_caps = data[offset]
        offset += 1

        capability_keys = None
        if has_caps:
            # Calculate capability keys size based on flags
            flags = data[offset]
            cap_size = 1  # flags byte
            cap_size += bin(flags).count("1") * CAPABILITY_KEY_SIZE
            capability_keys = CapabilityKeySet.from_bytes(
                data[offset : offset + cap_size]
            )
            offset += cap_size

        admin = cls(
            admin_id=admin_id,
            weight=weight,
            base_key=base_key,
            capability_keys=capability_keys,
        )

        return admin, offset

    @classmethod
    def generate(
        cls, admin_id: str, weight: int, with_capabilities: bool = True
    ) -> "Admin":
        """
        Generate a new admin with random keys.

        Args:
            admin_id: Unique identifier
            weight: Coalition weight
            with_capabilities: If True, generate all capability keys

        Returns:
            New Admin instance
        """
        base_key = os.urandom(ADMIN_KEY_SIZE)
        capability_keys = (
            CapabilityKeySet.generate_full() if with_capabilities else None
        )

        return cls(
            admin_id=admin_id,
            weight=weight,
            base_key=base_key,
            capability_keys=capability_keys,
        )


class AdminRegistry:
    """
    Manages the collection of administrators.

    Tracks admins and validates coalition formations.
    """

    def __init__(self, threshold: int):
        """
        Initialize registry with threshold.

        Args:
            threshold: Minimum combined weight for valid coalition (W)
        """
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")

        self.threshold = threshold
        self._admins: dict[str, Admin] = {}

    def add(self, admin: Admin) -> None:
        """
        Add an admin to the registry.

        Raises:
            ValueError: If admin_id already exists
        """
        if admin.admin_id in self._admins:
            raise ValueError(f"Admin {admin.admin_id} already exists")
        self._admins[admin.admin_id] = admin

    def get(self, admin_id: str) -> Optional[Admin]:
        """Get admin by ID, or None if not found."""
        return self._admins.get(admin_id)

    def remove(self, admin_id: str) -> None:
        """Remove an admin."""
        del self._admins[admin_id]

    def list_all(self) -> list[Admin]:
        """Get all admins."""
        return list(self._admins.values())

    def get_weights(self, admin_ids: Optional[list[str]] = None) -> dict[str, int]:
        """
        Get weights for specified admins (or all if None).

        Args:
            admin_ids: List of admin IDs, or None for all

        Returns:
            Mapping of admin_id to weight
        """
        if admin_ids is None:
            return {a.admin_id: a.weight for a in self._admins.values()}

        return {
            aid: self._admins[aid].weight for aid in admin_ids if aid in self._admins
        }

    def validate_coalition(self, admin_ids: list[str]) -> bool:
        """
        Check if specified admins form a valid coalition.

        Args:
            admin_ids: List of participating admin IDs

        Returns:
            True if sum of weights >= threshold
        """
        total_weight = sum(
            self._admins[aid].weight for aid in admin_ids if aid in self._admins
        )
        return total_weight >= self.threshold

    def total_weight(self) -> int:
        """Get total weight of all admins."""
        return sum(a.weight for a in self._admins.values())

    def to_bytes(self) -> bytes:
        """Serialize entire registry."""
        result = bytearray()

        # Threshold (2 bytes)
        result.extend(self.threshold.to_bytes(2, "big"))

        # Number of admins
        result.append(len(self._admins))

        for admin in self._admins.values():
            admin_bytes = admin.to_bytes()
            result.extend(len(admin_bytes).to_bytes(2, "big"))
            result.extend(admin_bytes)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AdminRegistry":
        """Deserialize registry."""
        offset = 0

        threshold = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2

        registry = cls(threshold=threshold)

        num_admins = data[offset]
        offset += 1

        for _ in range(num_admins):
            admin_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2

            admin, _ = Admin.from_bytes(data[offset : offset + admin_len])
            offset += admin_len

            registry._admins[admin.admin_id] = admin

        return registry
