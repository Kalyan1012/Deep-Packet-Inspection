class HTTPExtractor:
    """
    Extracts the HTTP Host header from plaintext HTTP payloads.
    """

    @staticmethod
    def extract_host(payload: bytes) -> str | None:
        try:
            text = payload.decode("iso-8859-1", errors="ignore")
            if not text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                return None

            for line in text.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    return host or None

            return None
        except Exception:
            return None
