"""
Key and share storage for delegation system.

Manages persistent storage for:
    - Admin registry (with keys and capabilities)
    - User registry
    - Delegation session data
"""

from pathlib import Path
from typing import Optional

from .admin import AdminRegistry, Admin
from .user import UserRegistry, User
from ..crypto.delegation import AdminShare, DelegationKey


class KeyStore:
    """
    Persistent storage for keys and registries.

    Directory Structure:
        store_dir/
            admins.meta      # Admin registry
            users.meta       # User registry
            shares/          # Admin shares for delegation sessions
            delegations/     # Exported delegation keys
            userkeys/        # Exported user keys
    """

    ADMINS_META = "admins.meta"
    USERS_META = "users.meta"
    SHARES_DIR = "shares"
    DELEGATIONS_DIR = "delegations"
    USERKEYS_DIR = "userkeys"

    def __init__(self, store_dir: str | Path):
        """Initialize keystore at specified directory."""
        self.store_dir = Path(store_dir)
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create directory structure."""
        self.store_dir.mkdir(parents=True, exist_ok=True)
        (self.store_dir / self.SHARES_DIR).mkdir(exist_ok=True)
        (self.store_dir / self.DELEGATIONS_DIR).mkdir(exist_ok=True)
        (self.store_dir / self.USERKEYS_DIR).mkdir(exist_ok=True)

    # --- Admin Registry ---

    def save_admin_registry(self, registry: AdminRegistry) -> None:
        """Save admin registry."""
        path = self.store_dir / self.ADMINS_META
        with open(path, "wb") as f:
            f.write(registry.to_bytes())

    def load_admin_registry(self) -> Optional[AdminRegistry]:
        """Load admin registry."""
        path = self.store_dir / self.ADMINS_META
        if not path.exists():
            return None

        with open(path, "rb") as f:
            return AdminRegistry.from_bytes(f.read())

    # --- User Registry ---

    def save_user_registry(self, registry: UserRegistry) -> None:
        """Save user registry."""
        path = self.store_dir / self.USERS_META
        with open(path, "wb") as f:
            f.write(registry.to_bytes())

    def load_user_registry(self) -> Optional[UserRegistry]:
        """Load user registry."""
        path = self.store_dir / self.USERS_META
        if not path.exists():
            return None

        with open(path, "rb") as f:
            return UserRegistry.from_bytes(f.read())

    # --- Admin Shares ---

    def save_admin_share(self, admin_share: AdminShare) -> None:
        """Save an admin's shares."""
        filename = f"{admin_share.admin_id}.share"
        path = self.store_dir / self.SHARES_DIR / filename

        with open(path, "wb") as f:
            f.write(admin_share.to_bytes())

    def load_admin_share(self, admin_id: str) -> Optional[AdminShare]:
        """Load an admin's shares."""
        filename = f"{admin_id}.share"
        path = self.store_dir / self.SHARES_DIR / filename

        if not path.exists():
            return None

        with open(path, "rb") as f:
            return AdminShare.from_bytes(f.read())

    def export_admin_share(self, admin_id: str, export_path: str | Path) -> None:
        """Export admin shares to external file."""
        share = self.load_admin_share(admin_id)
        if share is None:
            raise ValueError(f"No shares found for admin {admin_id}")

        with open(export_path, "wb") as f:
            f.write(share.to_bytes())

    @staticmethod
    def import_admin_share(import_path: str | Path) -> AdminShare:
        """Import admin shares from external file."""
        with open(import_path, "rb") as f:
            return AdminShare.from_bytes(f.read())

    # --- Delegation Keys ---

    def save_delegation_key(self, name: str, delegation_key: DelegationKey) -> None:
        """Save a delegation key."""
        filename = f"{name}.delegation"
        path = self.store_dir / self.DELEGATIONS_DIR / filename

        with open(path, "wb") as f:
            f.write(delegation_key.to_bytes())

    def load_delegation_key(self, name: str) -> Optional[DelegationKey]:
        """Load a delegation key."""
        filename = f"{name}.delegation"
        path = self.store_dir / self.DELEGATIONS_DIR / filename

        if not path.exists():
            return None

        with open(path, "rb") as f:
            return DelegationKey.from_bytes(f.read())

    def export_delegation_key(self, name: str, export_path: str | Path) -> None:
        """Export delegation key to external file."""
        dk = self.load_delegation_key(name)
        if dk is None:
            raise ValueError(f"No delegation key found: {name}")

        with open(export_path, "wb") as f:
            f.write(dk.to_bytes())

    @staticmethod
    def import_delegation_key(import_path: str | Path) -> DelegationKey:
        """Import delegation key from external file."""
        with open(import_path, "rb") as f:
            return DelegationKey.from_bytes(f.read())

    # --- User Keys ---

    def export_user_key(self, user_id: str, export_path: str | Path) -> None:
        """Export user's key to external file."""
        registry = self.load_user_registry()
        if registry is None:
            raise ValueError("No users registered")

        user = registry.get(user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")

        with open(export_path, "wb") as f:
            f.write(user.to_bytes())

    @staticmethod
    def import_user_key(import_path: str | Path) -> User:
        """Import user from external file."""
        with open(import_path, "rb") as f:
            user, _ = User.from_bytes(f.read())
            return user
