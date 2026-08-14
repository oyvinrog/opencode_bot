"""Matrix transport and encrypted image command for the ELIZA bot."""

from __future__ import annotations

import asyncio
import argparse
import getpass
import io
import json
import logging
import mimetypes
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw
from nio import (
    AsyncClient,
    AsyncClientConfig,
    InviteMemberEvent,
    LoginResponse,
    MatrixRoom,
    RoomMessageText,
    UploadResponse,
)
from nio.exceptions import OlmUnverifiedDeviceError

from .eliza import Eliza

LOG = logging.getLogger("matrix_eliza")


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    homeserver: str
    user_id: str
    password: str | None
    data_dir: Path
    picture: Path | None
    allowed_rooms: frozenset[str]
    auto_join: bool
    require_encryption: bool
    ignore_unverified_devices: bool

    @classmethod
    def from_env(cls) -> "Settings":
        homeserver = os.environ.get("MATRIX_HOMESERVER", "").rstrip("/")
        user_id = os.environ.get("MATRIX_USER_ID", "")
        if not homeserver or not user_id:
            raise ValueError("MATRIX_HOMESERVER and MATRIX_USER_ID are required")

        rooms = frozenset(filter(None, (
            value.strip() for value in os.environ.get("MATRIX_ALLOWED_ROOMS", "").split(",")
        )))
        picture_value = os.environ.get("ELIZA_PICTURE")
        return cls(
            homeserver=homeserver,
            user_id=user_id,
            password=os.environ.get("MATRIX_PASSWORD"),
            data_dir=Path(os.environ.get("ELIZA_DATA_DIR", "./data")),
            picture=Path(picture_value) if picture_value else None,
            allowed_rooms=rooms,
            auto_join=env_bool("MATRIX_AUTO_JOIN", False),
            require_encryption=env_bool("MATRIX_REQUIRE_ENCRYPTION", True),
            ignore_unverified_devices=env_bool("MATRIX_IGNORE_UNVERIFIED_DEVICES", False),
        )


class MatrixElizaBot:
    def __init__(self, client: AsyncClient, settings: Settings) -> None:
        self.client = client
        self.settings = settings
        self.eliza = Eliza()
        self.started_ms = int(time.time() * 1000)

    def room_allowed(self, room: MatrixRoom) -> bool:
        return not self.settings.allowed_rooms or room.room_id in self.settings.allowed_rooms

    async def on_invite(self, room: MatrixRoom, event: InviteMemberEvent) -> None:
        if event.state_key != self.client.user_id:
            return
        if not self.settings.auto_join:
            LOG.info("Invited to %s; auto-join is disabled", room.room_id)
            return
        if self.settings.allowed_rooms and room.room_id not in self.settings.allowed_rooms:
            LOG.warning("Ignoring invite to room outside MATRIX_ALLOWED_ROOMS: %s", room.room_id)
            return
        response = await self.client.join(room.room_id)
        LOG.info("Join response for %s: %s", room.room_id, response)

    async def on_message(self, room: MatrixRoom, event: RoomMessageText) -> None:
        if event.sender == self.client.user_id or event.server_timestamp < self.started_ms:
            return
        if not self.room_allowed(room):
            return
        if self.settings.require_encryption and (not room.encrypted or not event.decrypted):
            LOG.warning("Ignoring unencrypted message in room %s", room.room_id)
            return

        body = event.body.strip()
        if body == "!send_pic":
            await self.send_picture(room.room_id)
        elif body == "!help":
            await self.send_text(room.room_id, "Talk to me, or use !send_pic to receive my picture.")
        elif body.startswith("!"):
            await self.send_text(room.room_id, "I don't know that command. Try !help.")
        else:
            await self.send_text(room.room_id, self.eliza.respond(body))

    async def send_text(self, room_id: str, body: str) -> None:
        try:
            response = await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": body},
                ignore_unverified_devices=self.settings.ignore_unverified_devices,
            )
            LOG.debug("Text send response: %s", response)
        except OlmUnverifiedDeviceError:
            LOG.error(
                "Cannot send: the room has unverified devices. Verify them, or explicitly set "
                "MATRIX_IGNORE_UNVERIFIED_DEVICES=true (weaker identity assurance)."
            )

    def picture_data(self) -> tuple[io.BytesIO, str, str, int, int, int]:
        if self.settings.picture:
            path = self.settings.picture
            raw = path.read_bytes()
            with Image.open(io.BytesIO(raw)) as image:
                width, height = image.size
                mime = Image.MIME.get(image.format or "") or mimetypes.guess_type(path.name)[0]
            return io.BytesIO(raw), path.name, mime or "application/octet-stream", len(raw), width, height

        image = Image.new("RGB", (512, 320), "#f4ead7")
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((45, 35, 467, 285), radius=35, fill="#22445b", outline="#101f2a", width=8)
        draw.ellipse((135, 100, 190, 155), fill="#a9e34b")
        draw.ellipse((322, 100, 377, 155), fill="#a9e34b")
        draw.arc((150, 130, 362, 245), start=15, end=165, fill="#a9e34b", width=10)
        draw.text((182, 55), "ELIZA", fill="#f4ead7", stroke_width=1)
        output = io.BytesIO()
        image.save(output, format="PNG")
        size = output.tell()
        output.seek(0)
        return output, "eliza.png", "image/png", size, image.width, image.height

    async def send_picture(self, room_id: str) -> None:
        try:
            data, filename, mime, size, width, height = self.picture_data()
        except (OSError, ValueError) as exc:
            LOG.exception("Could not read ELIZA_PICTURE")
            await self.send_text(room_id, f"I couldn't open my picture: {exc}")
            return

        response, encrypted_file = await self.client.upload(
            data,
            content_type=mime,
            filename=filename,
            encrypt=True,
            filesize=size,
        )
        if not isinstance(response, UploadResponse) or not encrypted_file:
            LOG.error("Encrypted upload failed: %s", response)
            await self.send_text(room_id, "I couldn't upload my picture just now.")
            return

        encrypted_file["url"] = response.content_uri
        content = {
            "body": filename,
            "msgtype": "m.image",
            "file": encrypted_file,
            "info": {"mimetype": mime, "size": size, "w": width, "h": height},
        }
        try:
            await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content=content,
                ignore_unverified_devices=self.settings.ignore_unverified_devices,
            )
        except OlmUnverifiedDeviceError:
            LOG.error("Picture uploaded, but cannot send it because the room has unverified devices")


def save_session(path: Path, response: LoginResponse, homeserver: str) -> None:
    payload = {
        "homeserver": homeserver,
        "user_id": response.user_id,
        "device_id": response.device_id,
        "access_token": response.access_token,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


async def create_client(settings: Settings) -> AsyncClient:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.chmod(stat.S_IRWXU)
    session_path = settings.data_dir / "session.json"
    store_path = settings.data_dir / "crypto_store"
    store_path.mkdir(parents=True, exist_ok=True)
    config = AsyncClientConfig(
        encryption_enabled=True,
        store_sync_tokens=True,
    )

    if session_path.exists():
        session = json.loads(session_path.read_text(encoding="utf-8"))
        if session["homeserver"].rstrip("/") != settings.homeserver:
            raise ValueError("Stored session homeserver differs from MATRIX_HOMESERVER")
        if session["user_id"] != settings.user_id:
            raise ValueError("Stored session user differs from MATRIX_USER_ID")
        client = AsyncClient(
            settings.homeserver,
            session["user_id"],
            device_id=session["device_id"],
            store_path=str(store_path),
            config=config,
        )
        client.restore_login(
            user_id=session["user_id"],
            device_id=session["device_id"],
            access_token=session["access_token"],
        )
        return client

    client = AsyncClient(
        settings.homeserver,
        settings.user_id,
        store_path=str(store_path),
        config=config,
    )
    password = settings.password or getpass.getpass(f"Password for {settings.user_id}: ")
    response = await client.login(password=password, device_name="ELIZA bot")
    if not isinstance(response, LoginResponse):
        await client.close()
        raise RuntimeError(f"Matrix login failed: {response}")
    save_session(session_path, response, settings.homeserver)
    LOG.info("Created Matrix device %s; verify this device in your Matrix client", response.device_id)
    return client


async def run() -> None:
    settings = Settings.from_env()
    client = await create_client(settings)
    bot = MatrixElizaBot(client, settings)
    client.add_event_callback(bot.on_message, RoomMessageText)
    client.add_event_callback(bot.on_invite, InviteMemberEvent)
    LOG.info("ELIZA is logged in as %s on device %s", client.user_id, client.device_id)
    try:
        await client.sync_forever(timeout=30_000, full_state=True, set_presence="online")
    finally:
        await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the end-to-end encrypted Matrix ELIZA bot (configured via environment variables)."
    )
    parser.parse_args()
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
