"""
Capability key management for delegation with access rights.

Defines three capability levels:
    - READ: View data only
    - WRITE: Modify existing data
    - DELETE: Remove data

Each admin can generate capability keys that are combined with the
delegation secret to create capability-enhanced delegation keys.
"""

import os
import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


# Size of capability keys (256 bits)
CAPABILITY_KEY_SIZE = 32


class Capability(Enum):
    """Access capability types."""

    READ = auto()
    WRITE = auto()
    DELETE = auto()


@dataclass(frozen=True)
class CapabilityKey:
    """
    A capability key for a specific operation.

    Attributes:
        capability: The access right this key grants
        key: 256-bit random key
    """

    capability: Capability
    key: bytes

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format: 1 byte (capability ordinal) + 32 bytes (key)
        """
        return bytes([self.capability.value]) + self.key

    @classmethod
    def from_bytes(cls, data: bytes) -> "CapabilityKey":
        """Deserialize from binary format."""
        if len(data) < 1 + CAPABILITY_KEY_SIZE:
            raise ValueError(f"Data too short: {len(data)}")

        capability = Capability(data[0])
        key = data[1 : 1 + CAPABILITY_KEY_SIZE]
        return cls(capability=capability, key=key)

    @classmethod
    def generate(cls, capability: Capability) -> "CapabilityKey":
        """Generate a new random capability key."""
        key = os.urandom(CAPABILITY_KEY_SIZE)
        return cls(capability=capability, key=key)


@dataclass
class CapabilityKeySet:
    """
    Complete set of capability keys for an admin.

    An admin may have some or all capability keys.
    """

    read_key: Optional[CapabilityKey] = None
    write_key: Optional[CapabilityKey] = None
    delete_key: Optional[CapabilityKey] = None

    def get(self, capability: Capability) -> Optional[CapabilityKey]:
        """Get key for specific capability."""
        if capability == Capability.READ:
            return self.read_key
        elif capability == Capability.WRITE:
            return self.write_key
        elif capability == Capability.DELETE:
            return self.delete_key
        return None

    def has_capability(self, capability: Capability) -> bool:
        """Check if this set includes the specified capability."""
        return self.get(capability) is not None

    def get_capabilities(self) -> set[Capability]:
        """Get all capabilities in this set."""
        caps = set()
        if self.read_key:
            caps.add(Capability.READ)
        if self.write_key:
            caps.add(Capability.WRITE)
        if self.delete_key:
            caps.add(Capability.DELETE)
        return caps

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format: 1 byte (flags) + key data for each present key
        Flags: bit 0 = read, bit 1 = write, bit 2 = delete
        """
        flags = 0
        data = bytearray()

        if self.read_key:
            flags |= 1
            data.extend(self.read_key.key)
        if self.write_key:
            flags |= 2
            data.extend(self.write_key.key)
        if self.delete_key:
            flags |= 4
            data.extend(self.delete_key.key)

        return bytes([flags]) + bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CapabilityKeySet":
        """Deserialize from binary format."""
        flags = data[0]
        offset = 1

        read_key = None
        write_key = None
        delete_key = None

        if flags & 1:
            read_key = CapabilityKey(
                capability=Capability.READ,
                key=data[offset : offset + CAPABILITY_KEY_SIZE],
            )
            offset += CAPABILITY_KEY_SIZE

        if flags & 2:
            write_key = CapabilityKey(
                capability=Capability.WRITE,
                key=data[offset : offset + CAPABILITY_KEY_SIZE],
            )
            offset += CAPABILITY_KEY_SIZE

        if flags & 4:
            delete_key = CapabilityKey(
                capability=Capability.DELETE,
                key=data[offset : offset + CAPABILITY_KEY_SIZE],
            )
            offset += CAPABILITY_KEY_SIZE

        return cls(read_key=read_key, write_key=write_key, delete_key=delete_key)

    @classmethod
    def generate_full(cls) -> "CapabilityKeySet":
        """Generate a complete set with all capabilities."""
        return cls(
            read_key=CapabilityKey.generate(Capability.READ),
            write_key=CapabilityKey.generate(Capability.WRITE),
            delete_key=CapabilityKey.generate(Capability.DELETE),
        )


def hash_capability_keys(
    base_secret: bytes, capability_keys: list[CapabilityKey]
) -> bytes:
    """
    Compute composite secret: s' = H(s || K^op_1 || K^op_2 || ...)

    Sorts capability keys by type to ensure deterministic ordering.

    Args:
        base_secret: The base secret s from SSS reconstruction
        capability_keys: List of capability keys to include

    Returns:
        32-byte hash output
    """
    # Sort by capability type for deterministic ordering
    sorted_keys = sorted(capability_keys, key=lambda k: k.capability.value)

    # Concatenate: s || K1 || K2 || ...
    data = bytearray(base_secret)
    for cap_key in sorted_keys:
        data.extend(cap_key.key)

    # Hash with SHA-256
    return hashlib.sha256(bytes(data)).digest()
