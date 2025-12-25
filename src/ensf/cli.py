"""
CLI application for ENSF delegation-based access control.

Commands:
    init           Initialize system with threshold
    add-admin      Add an administrator
    add-user       Add a user
    delegate       Create delegation key (Scheme 1 or 2)
    encrypt        Encrypt user data
    decrypt        Decrypt user data
    list           List admins and users
    export         Export keys/shares
"""

import sys
from pathlib import Path
from typing import Optional, List

import typer

from .core.keystore import KeyStore
from .core.admin import Admin, AdminRegistry
from .core.user import User, UserRegistry
from .crypto.delegation import (
    DelegationScheme,
    DelegationKey,
    AdminShare,
    compose_user_key,
)
from .crypto.capability import Capability, CapabilityKey
from .crypto.aes import encrypt, decrypt, EncryptedData


app = typer.Typer(
    name="ensf", help="Delegation-based Access Control with Weighted Secret Sharing"
)

# Default keystore directory
DEFAULT_STORE = Path.home() / ".ensf"


def get_keystore(store_dir: Optional[Path] = None) -> KeyStore:
    """Get KeyStore instance."""
    if store_dir is None:
        store_dir = DEFAULT_STORE
    return KeyStore(store_dir)


@app.command()
def init(
    threshold: int = typer.Option(
        ..., "--threshold", "-t", help="Coalition weight threshold (W)"
    ),
    store_dir: Optional[Path] = typer.Option(
        None, "--store", "-s", help="Key storage directory"
    ),
) -> None:
    """
    Initialize the system with a threshold.

    The threshold W determines the minimum combined weight
    required for a valid admin coalition.
    """
    keystore = get_keystore(store_dir)

    # Check if already initialized
    if keystore.load_admin_registry() is not None:
        typer.echo("Error: System already initialized.", err=True)
        raise typer.Exit(1)

    # Create empty registries
    admin_registry = AdminRegistry(threshold=threshold)
    user_registry = UserRegistry()

    keystore.save_admin_registry(admin_registry)
    keystore.save_user_registry(user_registry)

    typer.echo(f"System initialized with threshold W = {threshold}")
    typer.echo(f"Key store: {keystore.store_dir}")


@app.command("add-admin")
def add_admin(
    admin_id: str = typer.Argument(..., help="Admin identifier (e.g., admin1)"),
    weight: int = typer.Option(1, "--weight", "-w", help="Coalition weight"),
    with_caps: bool = typer.Option(
        True, "--caps/--no-caps", help="Generate capability keys"
    ),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """
    Add a new administrator.

    Generates base key and optionally capability keys
    (read, write, delete) for delegation.
    """
    keystore = get_keystore(store_dir)
    registry = keystore.load_admin_registry()

    if registry is None:
        typer.echo("Error: System not initialized. Run 'ensf init' first.", err=True)
        raise typer.Exit(1)

    try:
        admin = Admin.generate(
            admin_id=admin_id, weight=weight, with_capabilities=with_caps
        )
        registry.add(admin)
        keystore.save_admin_registry(registry)

        typer.echo(f"Admin '{admin_id}' added (weight: {weight})")
        if with_caps:
            typer.echo("  Capability keys: read, write, delete")
        typer.echo(f"  Total system weight: {registry.total_weight()}")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command("add-user")
def add_user(
    user_id: str = typer.Argument(..., help="User identifier"),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """
    Add a new user.

    Generates a private key for the user.
    """
    keystore = get_keystore(store_dir)
    registry = keystore.load_user_registry()

    if registry is None:
        typer.echo("Error: System not initialized.", err=True)
        raise typer.Exit(1)

    try:
        user = User.generate(user_id=user_id)
        registry.add(user)
        keystore.save_user_registry(registry)

        typer.echo(f"User '{user_id}' added")
        typer.echo(f"Export key: ensf export user-key {user_id} -o {user_id}.key")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def delegate(
    admins: str = typer.Option(..., "--admins", "-a", help="Comma-separated admin IDs"),
    name: str = typer.Option(..., "--name", "-n", help="Delegation key name"),
    caps: Optional[str] = typer.Option(
        None, "--caps", "-c", help="Capabilities: read,write,delete"
    ),
    cap_provider: Optional[str] = typer.Option(
        None, "--cap-provider", "-p", help="Admin providing capability keys"
    ),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """
    Create a delegation key.

    Scheme 1 (no --caps): Basic delegation with read-only access.
    Scheme 2 (with --caps): Delegation with specified capabilities.

    Example:
        ensf delegate -a admin1,admin2 -n delegation1
        ensf delegate -a admin1,admin2 -n delegation2 -c read,write -p admin1
    """
    keystore = get_keystore(store_dir)
    admin_registry = keystore.load_admin_registry()

    if admin_registry is None:
        typer.echo("Error: System not initialized.", err=True)
        raise typer.Exit(1)

    admin_ids = [a.strip() for a in admins.split(",")]

    # Validate coalition
    if not admin_registry.validate_coalition(admin_ids):
        weights = admin_registry.get_weights(admin_ids)
        total = sum(weights.values())
        typer.echo(
            f"Error: Coalition weight {total} < threshold {admin_registry.threshold}",
            err=True,
        )
        raise typer.Exit(1)

    # Get weights for participating admins
    weights = admin_registry.get_weights(admin_ids)

    # Create delegation scheme
    scheme = DelegationScheme(threshold=admin_registry.threshold)

    # Generate and share secret
    secret = scheme.generate_secret()
    admin_shares = scheme.share_secret(secret, weights)

    # Save shares for each admin
    for admin_id, shares in admin_shares.items():
        admin_share = AdminShare(admin_id=admin_id, shares=shares)
        keystore.save_admin_share(admin_share)

    # Derive delegation key
    if caps:
        # Scheme 2: with capabilities
        if cap_provider is None:
            typer.echo("Error: --cap-provider required when using --caps", err=True)
            raise typer.Exit(1)

        provider = admin_registry.get(cap_provider)
        if provider is None or provider.capability_keys is None:
            typer.echo(f"Error: Admin {cap_provider} has no capability keys", err=True)
            raise typer.Exit(1)

        cap_list = [c.strip().lower() for c in caps.split(",")]
        capability_keys: list[CapabilityKey] = []

        for cap_name in cap_list:
            cap = Capability[cap_name.upper()]
            cap_key = provider.capability_keys.get(cap)
            if cap_key is None:
                typer.echo(
                    f"Error: {cap_provider} lacks {cap_name} capability", err=True
                )
                raise typer.Exit(1)
            capability_keys.append(cap_key)

        delegation_key = scheme.derive_delegation_key_scheme2(secret, capability_keys)
        typer.echo(f"Delegation key '{name}' created (Scheme 2)")
        typer.echo(f"  Capabilities: {', '.join(cap_list)}")
    else:
        # Scheme 1: basic (read-only)
        delegation_key = scheme.derive_delegation_key_scheme1(secret)
        typer.echo(f"Delegation key '{name}' created (Scheme 1)")
        typer.echo("  Capabilities: read-only")

    # Save delegation key
    keystore.save_delegation_key(name, delegation_key)
    typer.echo(f"  Coalition: {', '.join(admin_ids)}")


@app.command("encrypt")
def encrypt_data(
    user_id: str = typer.Option(..., "--user", "-u", help="User ID"),
    delegation: str = typer.Option(
        ..., "--delegation", "-d", help="Delegation key name"
    ),
    input_file: Path = typer.Argument(..., help="File to encrypt"),
    output_file: Path = typer.Argument(..., help="Output encrypted file"),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """
    Encrypt user data.

    Combines user key with delegation key to derive encryption key:
    K_U* = KDF(K_U || K_D)
    """
    keystore = get_keystore(store_dir)

    # Load user
    user_registry = keystore.load_user_registry()
    if user_registry is None:
        typer.echo("Error: No users registered.", err=True)
        raise typer.Exit(1)

    user = user_registry.get(user_id)
    if user is None:
        typer.echo(f"Error: User '{user_id}' not found.", err=True)
        raise typer.Exit(1)

    # Load delegation key
    delegation_key = keystore.load_delegation_key(delegation)
    if delegation_key is None:
        typer.echo(f"Error: Delegation key '{delegation}' not found.", err=True)
        raise typer.Exit(1)

    # Compose key
    composed_key = compose_user_key(user.key, delegation_key)

    # Read and encrypt
    with open(input_file, "rb") as f:
        plaintext = f.read()

    encrypted = encrypt(plaintext, composed_key)

    with open(output_file, "wb") as f:
        f.write(encrypted.to_bytes())

    typer.echo(f"Encrypted: {output_file}")
    typer.echo(f"  User: {user_id}")
    typer.echo(f"  Delegation: {delegation}")


@app.command("decrypt")
def decrypt_data(
    user_key_file: Path = typer.Option(..., "--user-key", "-u", help="User key file"),
    delegation_file: Path = typer.Option(
        ..., "--delegation", "-d", help="Delegation key file"
    ),
    input_file: Path = typer.Argument(..., help="Encrypted file"),
    output_file: Path = typer.Argument(..., help="Output decrypted file"),
) -> None:
    """
    Decrypt user data.

    Requires both user key and delegation key files.
    """
    try:
        # Load user key
        user = KeyStore.import_user_key(user_key_file)

        # Load delegation key
        delegation_key = KeyStore.import_delegation_key(delegation_file)

        # Compose key
        composed_key = compose_user_key(user.key, delegation_key)

        # Read and decrypt
        with open(input_file, "rb") as f:
            data = f.read()

        encrypted = EncryptedData.from_bytes(data)
        plaintext = decrypt(encrypted, composed_key)

        with open(output_file, "wb") as f:
            f.write(plaintext)

        typer.echo(f"Decrypted: {output_file}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command("list")
def list_entities(
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s")
) -> None:
    """
    List all admins and users.
    """
    keystore = get_keystore(store_dir)

    admin_registry = keystore.load_admin_registry()
    user_registry = keystore.load_user_registry()

    if admin_registry is None:
        typer.echo("System not initialized.")
        return

    typer.echo(f"Threshold: W = {admin_registry.threshold}")
    typer.echo("")

    typer.echo("Administrators:")
    typer.echo("-" * 50)
    for admin in admin_registry.list_all():
        caps = "yes" if admin.capability_keys else "no"
        typer.echo(f"  {admin.admin_id}: weight={admin.weight}, caps={caps}")

    if not admin_registry.list_all():
        typer.echo("  (none)")

    typer.echo("")
    typer.echo("Users:")
    typer.echo("-" * 50)

    if user_registry:
        for user in user_registry.list_all():
            typer.echo(f"  {user.user_id}")
        if not user_registry.list_all():
            typer.echo("  (none)")
    else:
        typer.echo("  (none)")


# Export subcommand group
export_app = typer.Typer(help="Export keys and shares")
app.add_typer(export_app, name="export")


@export_app.command("admin-share")
def export_admin_share(
    admin_id: str = typer.Argument(..., help="Admin ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file"),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """Export admin's shares to file."""
    keystore = get_keystore(store_dir)
    try:
        keystore.export_admin_share(admin_id, output)
        typer.echo(f"Exported: {output}")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@export_app.command("user-key")
def export_user_key(
    user_id: str = typer.Argument(..., help="User ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file"),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """Export user's key to file."""
    keystore = get_keystore(store_dir)
    try:
        keystore.export_user_key(user_id, output)
        typer.echo(f"Exported: {output}")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@export_app.command("delegation")
def export_delegation(
    name: str = typer.Argument(..., help="Delegation key name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file"),
    store_dir: Optional[Path] = typer.Option(None, "--store", "-s"),
) -> None:
    """Export delegation key to file."""
    keystore = get_keystore(store_dir)
    try:
        keystore.export_delegation_key(name, output)
        typer.echo(f"Exported: {output}")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
