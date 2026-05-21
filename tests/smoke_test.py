"""End-to-end smoke test for ultimatespeedwisp.

Tests:
1. v2 handshake (INFO/INFO/CONTINUE)
2. TCP stream CONNECT → DATA round-trip through echo server
3. Stream CLOSE
"""

import asyncio
import struct
import sys

import websockets

# Wisp packet builders
def build_info():
    """Client INFO: type=0x05, stream_id=0, major=2, minor=1"""
    return struct.pack('<BI', 0x05, 0) + bytes([2, 1])

def build_connect(stream_id, hostname, port, stream_type=0x01):
    """CONNECT: type=0x01, stream_id, stream_type, port_le16, hostname"""
    header = struct.pack('<BI', 0x01, stream_id)
    payload = struct.pack('<BH', stream_type, port) + hostname.encode()
    return header + payload

def build_data(stream_id, data):
    """DATA: type=0x02, stream_id, payload"""
    header = struct.pack('<BI', 0x02, stream_id)
    return header + data

def build_close(stream_id, reason=0x02):
    """CLOSE: type=0x04, stream_id, reason"""
    return struct.pack('<BIB', 0x04, stream_id, reason)

def parse_frame(data):
    """Parse a Wisp frame → (type, stream_id, payload)"""
    ptype = data[0]
    stream_id = struct.unpack_from('<I', data, 1)[0]
    payload = data[5:]
    return ptype, stream_id, payload


async def run_echo_server(host='127.0.0.1', port=9999):
    """Simple TCP echo server for testing."""
    async def handle_client(reader, writer):
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle_client, host, port)
    return server


async def main():
    # Start echo server
    echo_server = await run_echo_server()
    print("[echo] TCP echo server on 127.0.0.1:9999")

    try:
        async with websockets.connect(
            'ws://127.0.0.1:4000/',
            subprotocols=['wisp'],
            max_size=2**20,
        ) as ws:
            # === Step 1: Handshake ===
            server_info = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(server_info)
            assert ptype == 0x05, f"Expected INFO (0x05), got 0x{ptype:02x}"
            assert sid == 0, f"Expected stream_id 0, got {sid}"
            print(f"[ok] Server INFO: v{payload[0]}.{payload[1]}")

            await ws.send(build_info())

            initial_continue = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(initial_continue)
            assert ptype == 0x03, f"Expected CONTINUE (0x03), got 0x{ptype:02x}"
            assert sid == 0, f"Expected stream_id 0, got {sid}"
            buf_size = struct.unpack_from('<I', payload, 0)[0]
            print(f"[ok] Initial CONTINUE: buffer_size={buf_size}")

            # === Step 2: Open TCP stream to echo server ===
            stream_id = 1
            await ws.send(build_connect(stream_id, '127.0.0.1', 9999))

            # Should get CONTINUE for the new stream
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            ptype, sid, payload = parse_frame(resp)
            assert ptype == 0x03, f"Expected CONTINUE for stream, got 0x{ptype:02x}"
            assert sid == stream_id, f"Expected stream_id {stream_id}, got {sid}"
            print(f"[ok] Stream {stream_id} CONTINUE received")

            # === Step 3: Send DATA, receive echo ===
            test_data = b"Hello from ultimatespeedwisp test!"
            await ws.send(build_data(stream_id, test_data))

            # Read echoed DATA back
            resp = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(resp)
            assert ptype == 0x02, f"Expected DATA (0x02), got 0x{ptype:02x}"
            assert sid == stream_id, f"Expected stream_id {stream_id}, got {sid}"
            assert payload == test_data, f"Echo mismatch: {payload!r} != {test_data!r}"
            print(f"[ok] Echo round-trip: {len(test_data)} bytes")

            # === Step 4: Larger payload ===
            big_data = b"X" * 16384  # 16 KiB
            await ws.send(build_data(stream_id, big_data))

            resp = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(resp)
            assert ptype == 0x02 and sid == stream_id
            assert payload == big_data, f"Big echo mismatch: got {len(payload)} bytes"
            print(f"[ok] Large echo round-trip: {len(big_data)} bytes")

            # === Step 5: Close stream ===
            await ws.send(build_close(stream_id))
            print("[ok] Stream closed")

            # === Step 6: Close connection (stream 0) ===
            await ws.send(build_close(0))
            print("[ok] Connection close sent")

            print("\n=== ALL TESTS PASSED ===")

    except Exception as e:
        print(f"\n=== FAILED: {e} ===")
        sys.exit(1)
    finally:
        echo_server.close()
        await echo_server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
