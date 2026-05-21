"""Test the WS split refactor — verifies single and multi-stream echo."""
import asyncio
import struct
import sys
import websockets


def build_info():
    return struct.pack('<BI', 0x05, 0) + bytes([2, 1])

def build_connect(stream_id, hostname, port, stream_type=0x01):
    header = struct.pack('<BI', 0x01, stream_id)
    payload = struct.pack('<BH', stream_type, port) + hostname.encode()
    return header + payload

def build_data(stream_id, data):
    return struct.pack('<BI', 0x02, stream_id) + data

def build_close(stream_id, reason=0x02):
    return struct.pack('<BIB', 0x04, stream_id, reason)

def parse_frame(data):
    ptype = data[0]
    stream_id = struct.unpack_from('<I', data, 1)[0]
    payload = data[5:]
    return ptype, stream_id, payload


async def run_echo_server(port):
    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        writer.close()
    return await asyncio.start_server(handle, '127.0.0.1', port)


async def main():
    echo_server = await run_echo_server(9990)
    print("[echo] TCP echo server on 127.0.0.1:9990")

    try:
        async with websockets.connect(
            'ws://127.0.0.1:4000/',
            subprotocols=['wisp'],
            max_size=2**20,
        ) as ws:
            # === Handshake ===
            server_info = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(server_info)
            assert ptype == 0x05
            print(f"[ok] Server INFO: v{payload[0]}.{payload[1]}")

            await ws.send(build_info())

            cont = await asyncio.wait_for(ws.recv(), timeout=3)
            ptype, sid, payload = parse_frame(cont)
            assert ptype == 0x03
            buf_size = struct.unpack_from('<I', payload, 0)[0]
            print(f"[ok] Initial CONTINUE: buffer_size={buf_size}")

            # === Single stream echo ===
            await ws.send(build_connect(1, '127.0.0.1', 9990))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            ptype, sid, _ = parse_frame(resp)
            assert ptype == 0x03 and sid == 1
            print("[ok] Stream 1 CONTINUE")

            test_data = b"Hello from split test!"
            await ws.send(build_data(1, test_data))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            ptype, sid, payload = parse_frame(resp)
            assert ptype == 0x02 and sid == 1 and payload == test_data
            print(f"[ok] Stream 1 echo: {len(test_data)} bytes")

            # === Multi-stream: open 3 more streams ===
            for i in range(2, 5):
                await ws.send(build_connect(i, '127.0.0.1', 9990))
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                ptype, sid, _ = parse_frame(resp)
                assert ptype == 0x03 and sid == i, f"Expected CONTINUE for stream {i}, got type=0x{ptype:02x} sid={sid}"
                print(f"[ok] Stream {i} CONTINUE")

            # === Send data on all 4 streams, verify echo ===
            for i in range(1, 5):
                msg = f"stream-{i}-data".encode()
                await ws.send(build_data(i, msg))

            received = {}
            for _ in range(4):
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                ptype, sid, payload = parse_frame(resp)
                assert ptype == 0x02, f"Expected DATA, got 0x{ptype:02x}"
                received[sid] = payload

            for i in range(1, 5):
                expected = f"stream-{i}-data".encode()
                assert received.get(i) == expected, f"Stream {i}: expected {expected!r}, got {received.get(i)!r}"
            print("[ok] Multi-stream echo: 4 streams")

            # === Large payload on multiple streams ===
            big = b"Y" * 16384
            await ws.send(build_data(1, big))
            await ws.send(build_data(2, big))

            big_received = {}
            for _ in range(2):
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                ptype, sid, payload = parse_frame(resp)
                assert ptype == 0x02
                big_received[sid] = payload

            assert big_received[1] == big and big_received[2] == big
            print("[ok] Multi-stream large echo: 2 x 16KB")

            # === Close ===
            await ws.send(build_close(0))
            print("[ok] Connection close sent")
            print("\n=== ALL TESTS PASSED ===")

    except Exception as e:
        print(f"\n=== FAILED: {e} ===")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        echo_server.close()
        await echo_server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
