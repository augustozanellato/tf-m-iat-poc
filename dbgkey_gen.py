import sys

print("""
transport select swd

source [find target/swj-dp.tcl]

if { [info exists CHIPNAME] } {
        set _CHIPNAME $CHIPNAME
} else {
        set _CHIPNAME rp2350
}

if { [info exists WORKAREASIZE] } {
        set _WORKAREASIZE $WORKAREASIZE
} else {
        set _WORKAREASIZE 0x10000
}

if { [info exists CPUTAPID] } {
        set _CPUTAPID $CPUTAPID
} else {
        set _CPUTAPID 0x00040927
}

swj_newdap $_CHIPNAME swd -expected-id $_CPUTAPID
dap create $_CHIPNAME.dap -chain-position $_CHIPNAME.swd -adiv6

init

# Check idr
rp2350.dap apreg 0x80000 0xffc

# reset
rp2350.dap apreg 0x80000 4 0x4
""".strip())

key = int.from_bytes(bytes.fromhex(''.join(sys.argv[1:]).replace("0x", "").replace(" ", "").replace(",", ""))[:16], byteorder='big')
print(f"# key = 0x{key.to_bytes(16, byteorder='big', signed=False).hex()}")
for _ in range(128):
    print("rp2350.dap apreg 0x80000 0x4", hex(2 | (key & 1)))
    key >>= 1

print('\necho "Now attach a debugger to your RP2350 and load some code"')
