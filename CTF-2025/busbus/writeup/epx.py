from pwn import *
import time

context.log_level = 'warning'  # 减少输出噪音

s = remote("pwn-4ffe2dc69c.challenge.xctf.org.cn", 9999, ssl=True)

active_unit_ids = []

for i in range(201, 256):
    data = b"\x00\x01\x00\x00\x00\x06" + bytes([i]) + b"\x03\x00\x00\x00\x01"
    
    try:
        s.send(data)
        print(data)
        # 设置较短超时
        s.settimeout(0.3)
        try:
            response = s.recv(1024, timeout=0.3)
            if response:
                print(f"[+] 单元ID {i} 有响应: {response.hex()}")
                active_unit_ids.append(i)
        except:
            pass  # 无响应，继续下一个
        
        s.settimeout(None)
        
    except Exception as e:
        print(f"[-] 发送失败: {e}")
        break
    
    time.sleep(0.05)  # 更短的延迟

s.close()

print(f"\n[+] 发现活跃的单元ID: {active_unit_ids}")