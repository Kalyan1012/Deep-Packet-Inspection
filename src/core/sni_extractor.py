import dpkt

class SNIExtractor:
    """
    Extracts Server Name Indication (SNI) from TLS Client Hello packets.
    """

    @staticmethod
    def extract(payload: bytes) -> str | None:
        try:
            # 1. Unpack the outer TLS Record Layer
            tls_record = dpkt.ssl.TLSRecord(payload)

            # Type 22 = Handshake
            if tls_record.type != 22:
                return None

            # 2. Parse the Handshake Layer inside the record
            handshake = dpkt.ssl.TLSHandshake(tls_record.data)
            
            # Type 1 = Client Hello (where the browser announces the website name)
            if handshake.type != 1:
                return None

            # 3. Access the Client Hello data structures
            client_hello = handshake.data

            # 4. Loop through the TLS extensions to find the SNI extension
            if hasattr(client_hello, 'extensions'):
                for ext_id, ext_data in client_hello.extensions:
                    # Extension ID 0 is explicitly reserved for Server Name Indication (SNI)
                    if ext_id == 0:
                        # Unpack SNI extension structural bytes
                        # Skip the first 2 bytes (list length) and 1 byte (name type)
                        server_names = ext_data[2:]
                        if len(server_names) > 3:
                            name_len = int.from_bytes(server_names[1:3], byteorder='big')
                            domain_bytes = server_names[3:3 + name_len]
                            return domain_bytes.decode('utf-8', errors='ignore')

            return None

        except Exception:
            # Drop packets smoothly if TLS fragmentation or malformed extensions occur
            return None