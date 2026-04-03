"""OpenAI Whisper integration for audio message transcription."""
from __future__ import annotations

import io
import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class WhisperTranscriber:
    """Transcribe audio messages using the OpenAI Whisper API."""

    WHISPER_URL = "https://api.openai.com/v1/audio/transcriptions"
    SUPPORTED_EXTENSIONS = {".ogg", ".opus", ".m4a", ".mp3", ".wav", ".webm", ".mp4", ".mpeg", ".mpga"}
    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB (OpenAI limit)
    DEFAULT_MODEL = "whisper-1"

    async def transcribe_url(
        self,
        audio_url: str,
        api_key: str,
        *,
        language: str | None = None,
        timeout: float = 30.0,
    ) -> str:
        """Download audio from a URL and transcribe via Whisper API.

        Returns the transcribed text, or an empty string on failure.
        """
        url = str(audio_url or "").strip()
        key = str(api_key or "").strip()
        if not url or not key:
            return ""

        try:
            # 1. Download the audio file
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                dl_resp = await client.get(url)
                if dl_resp.status_code >= 400:
                    log.warning("whisper: failed to download audio url=%s status=%s", url[:80], dl_resp.status_code)
                    return ""
                audio_bytes = dl_resp.content
                if len(audio_bytes) > self.MAX_FILE_SIZE:
                    log.warning("whisper: audio too large (%s bytes), skipping", len(audio_bytes))
                    return ""

            # Guess filename from URL or use a sensible default
            filename = "audio.ogg"
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path
                if "." in path.rsplit("/", 1)[-1]:
                    filename = path.rsplit("/", 1)[-1][:64]
            except Exception:
                pass

            # 2. Call Whisper API
            files = {"file": (filename, io.BytesIO(audio_bytes), "audio/ogg")}
            data: dict[str, Any] = {"model": self.DEFAULT_MODEL}
            if language:
                data["language"] = language

            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    self.WHISPER_URL,
                    headers={"Authorization": f"Bearer {key}"},
                    files=files,
                    data=data,
                )
                if resp.status_code >= 400:
                    log.warning("whisper: API error status=%s body=%s", resp.status_code, resp.text[:200])
                    return ""
                result = resp.json()
                return str(result.get("text") or "").strip()

        except Exception as exc:
            log.warning("whisper: transcription failed url=%s err=%s", url[:80], exc)
            return ""

    async def transcribe_messages(
        self,
        messages: list[dict[str, Any]],
        api_key: str,
        *,
        max_audio: int = 5,
        language: str | None = None,
    ) -> list[dict[str, Any]]:
        """Enrich conversation messages by transcribing audio ones.

        For each audio message, adds an `audio_transcription` field and
        updates the `message` text to include the transcription so the LLM
        can read it.

        Returns the (possibly modified) messages list.
        """
        key = str(api_key or "").strip()
        if not key:
            return messages

        audio_count = 0
        enriched: list[dict[str, Any]] = []

        for msg in messages:
            msg_copy = dict(msg)
            msg_type = str(msg_copy.get("type") or "").strip().lower()
            is_audio = msg_type in ("audio", "voice", "ptt")
            audio_url = str(msg_copy.get("url") or msg_copy.get("media_url") or "").strip()

            if is_audio and audio_url and audio_count < max_audio:
                audio_count += 1
                transcript = await self.transcribe_url(audio_url, key, language=language)
                if transcript:
                    msg_copy["audio_transcription"] = transcript
                    # Replace or augment the message text so the LLM can read it
                    original_text = str(msg_copy.get("message") or "").strip()
                    if original_text:
                        msg_copy["message"] = f"{original_text}\n[صوت: {transcript}]"
                    else:
                        msg_copy["message"] = f"[صوت: {transcript}]"
                else:
                    msg_copy["message"] = str(msg_copy.get("message") or "[رسالة صوتية]")

            enriched.append(msg_copy)

        return enriched
