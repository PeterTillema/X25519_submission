INT_SIZE = 32
P_OFFSET = 19

; Code size: 168 bytes
; Relocation size: 984 bytes
; Data size: 321 bytes
; Read only data size: 64 bytes

    assume adl=1

define ti? ti
namespace ti?
?cursorImage               := 0E30800h
end namespace

    section .text
    public _tls_x25519_secret
    public _tls_x25519_publickey

; Some macros to make code more clear
macro swap in1, in2
    ld      de, in1
    ld      hl, in2
    call    _swap
end macro

macro fmul out, in1, in2
    ld      de, out
    ld      bc, in1
    ld      hl, in2
    call    _fmul
end macro

macro fadd out, in1, in2
    ld      de, out
    ld      bc, in1
    ld      hl, in2
    call    _fadd
end macro

macro fsub out, in1, in2
    ld      de, out
    ld      bc, in1
    ld      hl, in2
    call    _fsub
end macro

arg1 := 3
arg2 := 6
arg3 := 9
arg4 := 12
sparg1 := 6
sparg2 := 9
sparg3 := 12
sparg4 := 15
sparg5 := 18

_tls_x25519_publickey:
; Inputs:
;   arg1 = public_key
;   arg2 = private_key
;   arg3 = yield_fn
;   arg4 = yield_data
; Timing: _tls_x25519_secret + 313 cc
    ld      iy, 0
    add     iy, sp
    ld      hl, (iy + arg4)
    push    hl
    ld      hl, (iy + arg3)
    push    hl
    ld      hl, _9
    push    hl
    ld      hl, (iy + arg2)
    push    hl
    ld      hl, (iy + arg1)
    push    hl
    call    _tls_x25519_secret
    pop     hl, hl, hl, hl, hl
    ret

_tls_x25519_secret:
; Inputs:
;   arg1 = shared_secret (out)
;   arg2 = my_private (scalar)
;   arg3 = their_public (point)
;   arg4 = yield_fn
;   arg5 = yield_data
; Timing first attempt: 482,792,828 cc
; Timing current:       289,848,621 cc      ; Assuming yield_fn = NULL
scalar:
scalar.clampedPointer := 0                  ; A pointer to the current byte of scalar to check the bit against
scalar.clampedMask := 3                     ; A mask to check the scalar byte against. Rotates after the loop
scalar.clampedByte := 4                     ; The byte in the clamped array
scalar.mainLoopIndex := 5                   ; Main loop index
scalar.size := 6

    push    ix
    ld      ix, -scalar.size
    add     ix, sp
    ld      sp, ix
; Relocate code to be more performant
    ld      hl, reloc.data
    ld      de, ti.cursorImage
    ld      bc, reloc.data.len
    ldir
; Setup some variables
    ld      a, 1 shl 6
    ld      (ix + scalar.clampedMask), a
    sbc     a, a
    ld      (ix + scalar.mainLoopIndex), a
; Copy scalar to clamped, and edit byte 0 and byte 31
    ld      de, _clamped
    ld      hl, (ix + sparg2 + scalar.size)
    ld      a, (hl)
    and     a, 0xF8
    ld      (de), a
    inc     hl
    inc     de
    ld      c, INT_SIZE - 1
    ldir
    dec     de              ; DE = _clamped + INT_SIZE - 1
    ld      (ix + scalar.clampedPointer), de
    ld      a, (de)
    or      a, 0x40         ; and a, 0x7F is not necessary, as the last bit is not used at all
    ld      (de), a
    inc     de
; Fill _a to _d
    ld      a, 1            ; a[0] = 1
    ld      (de), a
    inc     de
    dec     a
    ld      (de), a
    inc     de              ; DE = _a + 2
    ld      c, INT_SIZE - 2 ; Clear _a
    ld      hl, _a + 1
    ldir
    ld      hl, (ix + sparg3 + scalar.size)    ; Copy point to b
    ld      c, INT_SIZE
    ldir
    ld      (de), a         ; Clear c
    inc     de
    ld      hl, _c
    ld      c, INT_SIZE - 1
    ldir
    ld      hl, _a          ; _d = _a
    ld      c, INT_SIZE
    ldir
    call    mainCalculationLoop
; Final multiplication, putting the result in out
    fmul (ix + sparg1 + scalar.size), _a, _c
    lea     hl, ix + scalar.size
    ld      sp, hl
    pop     ix
    ld      a, 1
    ret

virtual at ti.cursorImage
mainCalculationLoop:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;; CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ; A loops back from 255 to 1, so the current logic calls the yield_fn function every 100 loops (every ~3 seconds)
    ld      a, (ix + scalar.mainLoopIndex)
    cp      a, 155
    jr      z, .yieldFn
    cp      a, 55
    jr      nz, .noYieldFn
.yieldFn:
    ld      hl, (ix + scalar.size + sparg4)
    add     hl, de
    or      a, a
    sbc     hl, de
    jr      z, .noYieldFn
    ld      de, (ix + scalar.size + sparg5)
    push    de
    call    _jumpHL
    pop     de
.noYieldFn:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;; /CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ; Get bit
    ld      hl, (ix + scalar.clampedPointer)
    ld      a, (hl)
    and     a, (ix + scalar.clampedMask)
    ld      (ix + scalar.clampedByte), a
; First swaps
    add     a, -1           ; Set -> cf is true; reset -> cf is false
    swap _a, _b
    ld      a, (ix + scalar.clampedByte)
    add     a, -1
    swap _c, _d
; Do the main calculations!
    fadd _e, _a, _c
    fsub _a, _a, _c
    fadd _c, _b, _d
    fsub _b, _b, _d
    fmul _d, _e, _e
    fmul _f, _a, _a
    fmul _a, _c, _a
    fmul _c, _b, _e
    fadd _e, _a, _c
    fsub _a, _a, _c
    fmul _b, _a, _a
    fsub _c, _d, _f
    fmul _a, _c, _121665
    fadd _a, _a, _d
    fmul _c, _c, _a
    fmul _a, _d, _f
    fmul _d, _b, (ix + sparg3 + scalar.size)
    fmul _b, _e, _e
; Final swaps
    ld      a, (ix + scalar.clampedByte)
    add     a, -1
    swap _a, _b
    ld      a, (ix + scalar.clampedByte)
    add     a, -1
    swap _c, _d

; Get to the next bit
    rrc     (ix + scalar.clampedMask)
    jr      nc, .continue
    ld      hl, (ix + scalar.clampedPointer)
    dec     hl
    ld      (ix + scalar.clampedPointer), hl
.continue:
    dec     (ix + scalar.mainLoopIndex)
    jq      nz, mainCalculationLoop
; Copy _c to _b
    ld      de, _b
    ld      hl, _c
    ld      bc, INT_SIZE
    ldir
; Inverse _c
    ld      (ix + scalar.mainLoopIndex), 254
.inverseLoop:
    dec     (ix + scalar.mainLoopIndex)
    ret     z
    fmul _c, _c, _c
    ld      a, (ix + scalar.mainLoopIndex)
    cp      a, 2
    jr      z, .inverseLoop
    cp      a, 4
    jr      z, .inverseLoop
    fmul _c, _c, _b
    jr      .inverseLoop

_jumpHL:
    jp      (hl)

_fmul:
; Performs a multiplication between two big integers, and returns the result in mod p.
; It works because (a mod 2p) * (b mod 2p) = (a * b) mod 2p = (a * b) mod p. The pseudocode for multiplying looks like this:
;  - Reset first 32 bytes of product outcome to zeroes
;  - For each byte in input a, multiply the value with the entirety of b, and add to the product output at the correct offset.
;  - Now product is a 64-byte value, i.e.:
;      product = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^256 + t_33 * 2^264 + ... + t_63 * 2^504
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^0 * (2p + 38) + t_33 * 2^1 * (2p + 38) + ... + t_63 * 2^248 * (2p + 38)
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 38 * 2^0 + t_33 * 38 * 2^1 + ... + t_63 * 38 * 2^248 (mod 2p)
;              = (t_0 + 38 * t_32) * 2^0 + ... + (t_30 + 38 * t_62) * 2^240 + (t_31 + 38 * t_63) * 2^248 (mod 2p)
;    That means that for each index in the lower 32 bytes, we can add 38*product[index + 32] and the result becomes mod 2p.
;  - Calculate 38 times each byte in the second half of the product, and add it to the first half of the product output.
;  - The last byte from the intermediate result (the carry) will be propagated back, namely 38 * (value of last byte) will
;    be added to the first byte again. This can again trigger an overflow, so propagate the carry even further.
;  - The first 32 bytes of product now contains the output mod 2p, and will be copied to the out variable.
;  - Either out or out - p is used.
; Inputs:
;   DE = out
;   BC = a mod 2p
;   HL = b mod 2p
mul:
mul.productOutputPointer := 0               ; A pointer to where the product output should be stored
mul.outerLoopCount := 3                     ; Main count down
mul.arg1 := 4
mul.arg2 := 7
mul.out := 10
mul.size := 13

    push    ix
    ld      ix, -mul.size
    add     ix, sp
    ld      sp, ix
; Copy the input variables to the temporary storage
    ld      (ix + mul.arg1), bc
    ld      (ix + mul.arg2), hl
    ld      (ix + mul.out), de
; Setup the product output
    ld      hl, _product
    ld      (ix + mul.productOutputPointer), hl
    ld      bc, INT_SIZE - 1
    ld      (hl), b
    ld      de, _product + 1
    ldir
; Also setup the other variables
    ld      (ix + mul.outerLoopCount), INT_SIZE
    ld      hl, (ix + mul.arg1)
; Within a loop, get a single byte from a, and multiply it with the entirety of b, adding it to the product immediately
.mainLoop:
    ld      a, (hl)          ; a[index]
    inc     hl
    push    hl
    ld      iyh, a
    ld      iyl, INT_SIZE
    ld      de, (ix + mul.productOutputPointer)
    ld      hl, (ix + mul.arg2)
    xor     a, a            ; Reset carry + carry flag
.addMulSingleByteLoop:
    ld      c, (hl)
    inc     hl
    ld      b, iyh
    mlt     bc
    adc     a, c
    ld      c, a            ; Temporarily save a
    adc     a, b            ; b + cf -> b
    sub     a, c
    ld      b, a
    ld      a, (de)         ; Restore a and add to (de)
    add     a, c
    ld      (de), a
    ld      a, b
    inc     de
    dec     iyl
    jr      nz, .addMulSingleByteLoop
; Add the last carry byte to the product. Since we work from low to high indexes, this last carry byte is guarenteed to
; not overlap with the previous product result, thus storing it directly works properly.
    adc     a, 0
    ld      (de), a
; Continue with the main loop
    ld      hl, (ix + mul.productOutputPointer)
    inc     hl
    ld      (ix + mul.productOutputPointer), hl
    pop     hl
    dec     (ix + mul.outerLoopCount)
    jr      nz, .mainLoop

; For the lower 32 bytes of the product, calculate sum(38 * product[i + 32]) and add to product directly
    ld      de, _product
    ld      hl, _product + INT_SIZE
    xor     a, a                ; Reset carry for the next calculations
    ld      iyl, INT_SIZE
.addMul38Loop:
    ld      c, (hl)
    inc     hl
    ld      b, 38
    mlt     bc
    adc     a, c
    ld      c, a            ; Temporarily save a
    adc     a, b            ; b + cf -> b
    sub     a, c
    ld      b, a
    ld      a, (de)         ; Restore a and add to (de)
    add     a, c
    ld      (de), a
    ld      a, b
    inc     de
    dec     iyl
    jr      nz, .addMul38Loop
; Propagate the last carry byte back to the first falue
    adc     a, 0
    ld      c, a
    ld      b, 38
    mlt     bc
    ld      hl, _product
    ld      de, (hl)
    ex      de, hl
    add     hl, bc
    ex      de, hl
    ld      (hl), de
    inc     hl
    inc     hl
    inc     hl
    ld      bc, 0
repeat (INT_SIZE - 3) / 3
    ld      de, (hl)
    ex      de, hl
    adc     hl, bc
    ex      de, hl
    ld      (hl), de
    inc     hl
    inc     hl
    inc     hl
end repeat
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
; Copy product to out
    ld      de, (ix + mul.out)
    ld      hl, _product
    ld      c, INT_SIZE
    ldir
    ld      de, (ix + mul.out)
; We don't need ix anymore, so pop in advance
    lea     hl, ix + mul.size
    ld      sp, hl
    pop     ix
; Perform the pack to calculate mod p instead of mod 2p
    ld      hl, _product
    push    hl
; Subtract p from temp (inline)
    ld      a, (hl)
    sub     a, -P_OFFSET
    ld      (hl), a
    dec     c               ; c = -1
repeat INT_SIZE - 2
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
end repeat
    inc     hl              ; Same as within the loop, but now 7F to not subtract the last bit
    ld      a, (hl)
    sbc     a, 0x7F
    ld      (hl), a
    ccf                     ; If the carry flag WAS set, out < p, so no swap needed. Flip the carry flag and call the swap
    pop     hl              ; hl -> temp

_swap:
; Eventually swaps 2 big integers based on the carry flag. Performs the swap in constant time to prevent timing attacks
; Inputs:
;   DE = a
;   HL = b
;   cf = swap or not
; Size: 21 bytes
; Timing: 2756cc
    sbc     a, a
    ld      c, a            ; c = cf ? 0xFF : 0
    ld      iyl, INT_SIZE
.swapLoop:
    ld      a, (de)         ; t = c & (a[i] ^ b[i])
    xor     a, (hl)
    and     a, c
    ld      b, a
    xor     a, (hl)         ; b[i] ^= t
    ld      (hl), a
    ld      a, (de)         ; a[i] ^= t
    xor     a, b
    ld      (de), a
    inc     hl
    inc     de
    dec     iyl
    jr      nz, .swapLoop
    ret

_fadd:
; Performs an addition between two big integers mod p, and returns the result without any mod. This is possible because
; the output is used as an input for multiplication, which handles overflows itself.
; Inputs:
;   DE = out
;   BC = a mod p
;   HL = b mod p
    xor     a, a            ; Reset carry flag
    ld      iyl, INT_SIZE
.addLoop:
    ld      a, (bc)         ; out[i] = a[i] + b[i] + carry
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    inc     bc
    dec     iyl
    jr      nz, .addLoop
    ret

_fsub:
; Performs a subtraction between two big integers mod p, and returns the result in mod p again.
; It works because (a mod p) - (b mod p) = (a - b) mod p.
; Inputs:
;   DE = out
;   BC = a mod p
;   HL = b mod p
    xor     a, a            ; Reset carry flag
    ld      iyl, INT_SIZE
.subtractLoop:
    ld      a, (bc)         ; out[i] = a[i] - b[i] - carry
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    inc     bc
    dec     iyl
    jr      nz, .subtractLoop
; Now out is in the range (-2^255+19, 2^255-19). In order to do a mod p, we copy out to a temp variable, add p to
; that and eventually swap places (all in constant time), such that either out or (out + p) is used.
    dec     de
    ex      de, hl          ; hl -> out + 31
    ld      de, _temp + INT_SIZE - 1
    ld      bc, INT_SIZE
    lddr
    ex      de, hl
    inc     hl              ; hl -> temp
    inc     de              ; de -> out
    push    hl
; Add p to temp (inline)
    ld      a, (hl)
    add     a, -P_OFFSET
    ld      (hl), a
    ld      b, INT_SIZE - 2
.addLoop:
    inc     hl
    ld      a, (hl)
    adc     a, 0xFF
    ld      (hl), a
    djnz    .addLoop
    inc     hl              ; Same as within the loop, but now 7F to not add the last bit
    ld      a, (hl)
    adc     a, 0x7F
    ld      (hl), a
    pop     hl              ; hl -> temp
    jq      _swap

    private	reloc_rodata
load reloc_rodata: $-$$ from $$
end virtual


repeat 1, x:$-_tls_x25519_publickey
    display 'Code size: ', `x, ' bytes', 10
end repeat

repeat 1, x:reloc.data.len
    display 'Relocation size: ', `x, ' bytes', 10
end repeat

    section	.data
    private	reloc.data
    private	reloc.data.len
reloc.data:
    db	reloc_rodata
.len := $-.
reloc.base := ti.cursorImage
reloc.offset := reloc.base - reloc.data

    section .data
    private _clamped
    private _a
    private _b
    private _c
    private _d
    private _e
    private _f
    private _product
    private _temp

; Used for scalar
_clamped:
    rb      INT_SIZE
_a:
    rb      INT_SIZE
_b:
    rb      INT_SIZE
_c:
    rb      INT_SIZE
_d:
    rb      INT_SIZE
_e:
    rb      INT_SIZE
_f:
    rb      INT_SIZE
; Used for multiplication
_product:
    rb      INT_SIZE * 2
_temp:
    rb      INT_SIZE + 1


repeat 1, x:$-_clamped
    display 'Data size: ', `x, ' bytes', 10
end repeat


    section .rodata
    private _9
    private _121665

_9:
    db      0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

_121665:
    db      0x41, 0xDB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00


repeat 1, x:$-_9
    display 'Read only data size: ', `x, ' bytes', 10
end repeat
