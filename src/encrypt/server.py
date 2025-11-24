"""
Async TLS relay: Stores clients by PK, relays msgs, echoes acks. 
Detects simple replays via timestamp validation.
"""
import asyncio
import ssl
from typing import Dict
from encrypt.protocol import unpack_connect, pack_ack, unpack_message, MSG_TYPES

class RelayServer:
    def __init__(self, host: str = '127.0.0.1', port: int = 8888):
        self.host = host
        self.port = port
        self.clients: Dict[bytes, asyncio.StreamWriter] = {}  # PK -> writer

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        pk = None
        
        print(f"Client connected: {addr}")
        
        try:
            # Handshake
            data = await reader.read(1024)
            conn = unpack_connect(data)
            
            if not conn or conn.get('type') != MSG_TYPES['connect']:
                writer.close()
                await writer.wait_closed()
                return
            
            pk = bytes(conn['pk'])
            self.clients[pk] = writer
            print(f"Registered: {pk.hex()[:8]}...")
            
            # Echo ack to client
            writer.write(pack_ack(b''))
            await writer.drain()
            
            # Relay loop
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                msg = unpack_message(data)
                if not msg:
                    print(f"Invalid/stale message from {pk.hex()[:8]}")
                    continue
                
                # Relay to target
                to_pk = bytes(msg['to'])
                if to_pk in self.clients:
                    target_writer = self.clients[to_pk]
                    target_writer.write(data)
                    await target_writer.drain()
                    print(f"Relayed {len(data)}B: {pk.hex()[:8]} -> {to_pk.hex()[:8]}")
                else:
                    print(f"Unknown target: {to_pk.hex()[:8]}")
                
                # Ack to sender (echo hash)
                writer.write(pack_ack(msg['h']))
                await writer.drain()
                
        except asyncio.CancelledError:
            print(f"Handler cancelled for {addr}")
        except Exception as e:
            print(f"Handler error for {addr}: {e}")
        finally:
            if pk and pk in self.clients:
                del self.clients[pk]
                print(f"Unregistered: {pk.hex()[:8]}")
            
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            
            print(f"Client disconnected: {addr}")

    async def start(self, ssl_context: ssl.SSLContext):
        server = await asyncio.start_server(
            self.handle_client, 
            self.host, 
            self.port, 
            ssl=ssl_context
        )
        
        print(f"TLS relay listening on {self.host}:{self.port}")
        
        async with server:
            await server.serve_forever()


async def run():
    """Main server entry point."""
    # Load TLS cert
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain('cert.pem', 'key.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # Demo only
    
    relay = RelayServer()
    await relay.start(ssl_ctx)


def main():
    """Entry point for server."""
    asyncio.run(run())


if __name__ == '__main__':
    main()
