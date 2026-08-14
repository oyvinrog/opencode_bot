from types import SimpleNamespace
from unittest.mock import AsyncMock

from nio import UploadResponse

from matrix_eliza_bot.bot import MatrixElizaBot, Settings


def settings(tmp_path, **changes):
    values = {
        "homeserver": "https://matrix.example",
        "user_id": "@eliza:example",
        "password": None,
        "data_dir": tmp_path,
        "picture": None,
        "allowed_rooms": frozenset(),
        "auto_join": False,
        "require_encryption": True,
        "ignore_unverified_devices": False,
    }
    values.update(changes)
    return Settings(**values)


async def test_picture_is_uploaded_encrypted_and_sent_as_file(tmp_path) -> None:
    upload = UploadResponse.from_dict({"content_uri": "mxc://example/encrypted"})
    client = SimpleNamespace(
        user_id="@eliza:example",
        upload=AsyncMock(return_value=(upload, {"v": "v2", "key": {"kty": "oct"}})),
        room_send=AsyncMock(),
    )
    bot = MatrixElizaBot(client, settings(tmp_path))

    await bot.send_picture("!room:example")

    upload_kwargs = client.upload.await_args.kwargs
    assert upload_kwargs["encrypt"] is True
    send_content = client.room_send.await_args.kwargs["content"]
    assert client.room_send.await_args.kwargs["ignore_unverified_devices"] is False
    assert "url" not in send_content
    assert send_content["file"]["url"] == "mxc://example/encrypted"
    assert send_content["msgtype"] == "m.image"


async def test_unencrypted_room_is_ignored(tmp_path) -> None:
    client = SimpleNamespace(user_id="@eliza:example", room_send=AsyncMock())
    bot = MatrixElizaBot(client, settings(tmp_path))
    event = SimpleNamespace(
        sender="@person:example",
        server_timestamp=bot.started_ms + 1,
        body="Hello",
        decrypted=False,
    )
    room = SimpleNamespace(room_id="!room:example", encrypted=False)

    await bot.on_message(room, event)

    client.room_send.assert_not_awaited()
