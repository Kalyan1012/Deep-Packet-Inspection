import dpkt


class SNIExtractor:
    """
    Extracts Server Name Indication (SNI)
    from TLS Client Hello packets.
    """

    @staticmethod
    def extract(payload: bytes) -> str | None:
        try:
            tls_record = dpkt.ssl.TLSRecord(payload)

            if tls_record.type != 22:
                return None

            return "unknown-tls-domain"

        except Exception:
            return None