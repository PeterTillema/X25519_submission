INT_SIZE = 32
P_OFFSET = 19

; Code size: 713 bytes
; Relocation size: 981 bytes
; Data size: 288 bytes
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
macro copy source, out
    ld      de, out
    ld      hl, source
    ld      bc, INT_SIZE
    ldir
end macro

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
    copy in1, out
    ld      de, out
    ld      hl, in2
    call    _faddInline
end macro

macro faddInline out, in2
    ld      de, out
    ld      hl, in2
    call    _faddInline
end macro

macro fsubInline out, in2
    ld      de, out
    ld      hl, in2
    call    _fsubInline
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
; Timing current:       225,342,248 cc      ; Assuming yield_fn = NULL
tempVariables:
scalar:
scalar.clampedPointer := 0                  ; A pointer to the current byte of scalar to check the bit against
scalar.clampedMask := 3                     ; A mask to check the scalar byte against. Rotates after the loop
scalar.clampedByte := 4                     ; The byte in the clamped array
scalar.mainLoopIndex := 5                   ; Main loop index
mul:
mul.outerLoopCount := 6                     ; Main count down
mul.arg2 := 7

tempVariables.size := 10

    push    ix
    ld      ix, -tempVariables.size
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
    ld      hl, (ix + sparg2 + tempVariables.size)
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
    ld      hl, (ix + sparg3 + tempVariables.size)    ; Copy point to b
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
    lea     hl, ix + tempVariables.size
    ld      sp, hl
    pop     ix
    ld      a, 1
    ret

mainCalculationLoop:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;; CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ; A loops back from 255 to 1, so the current logic calls the yield_fn function after 128 loops (every ~2.75 seconds)
    ld      a, (ix + scalar.mainLoopIndex)
    cp      a, 128
    jr      nz, .noYieldFn
    ld      hl, (ix + tempVariables.size + sparg4)
    add     hl, de
    or      a, a
    sbc     hl, de
    jr      z, .noYieldFn
    ld      de, (ix + tempVariables.size + sparg5)
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
    add     a, -1           ; Set -> cf is true; reset -> cf is false
    sbc     a, a
    ld      (ix + scalar.clampedByte), a
    ld      c, a
; First swaps
    swap _a, _b
    ld      c, (ix + scalar.clampedByte)
    swap _c, _d
; Do the main calculations!
    fadd _e, _a, _c
    fsubInline _a, _c
    fadd _c, _b, _d
    fsubInline _b, _d
    fmul _d, _e, _e
    fmul _f, _a, _a
    fmul _a, _c, _a
    fmul _c, _b, _e
    fadd _e, _a, _c
    fsubInline _a, _c
    fmul _b, _a, _a
    copy _d, _c
    fsubInline _c, _f
    fmul _a, _c, _121665
    faddInline _a, _d
    fmul _c, _c, _a
    fmul _a, _d, _f
    fmul _d, _b, (ix + sparg3 + tempVariables.size)
    fmul _b, _e, _e
; Final swaps
    ld      c, (ix + scalar.clampedByte)
    swap _a, _b
    ld      c, (ix + scalar.clampedByte)
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
    fmul _c, _c, _c
    ld      a, (ix + scalar.mainLoopIndex)
    cp      a, 3
    jr      z, .continue2
    cp      a, 5
    jr      z, .continue2
    fmul _c, _c, _b
.continue2:
    dec     (ix + scalar.mainLoopIndex)
    jr      nz, .inverseLoop
; Final multiplication, putting the result in out
    fmul (ix + sparg1 + tempVariables.size), _a, _c
; Out is now in mod 2p, calculate the actual mod p by subtracting p and performing a swap if necessary
    ld      hl, (ix + sparg1 + tempVariables.size)
; Perform the pack to calculate mod p instead of mod 2p
    ld      de, _product
    push    de, hl
; Subtract p from out and store to _product
    ld      a, (hl)
    sub     a, -P_OFFSET
    ld      (de), a
    ld      b, INT_SIZE - 2
    dec     c               ; c = -1
.subtractLoop:
    inc     de
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (de), a
    djnz    .subtractLoop
    inc     de              ; Same as within the loop, but now 7F to not subtract the last bit
    inc     hl
    ld      a, (hl)
    sbc     a, 0x7F
    ld      (de), a
    ccf                     ; If the carry flag WAS set, out < p, so no swap needed. Flip the carry flag and call the swap
    pop     hl, de
    sbc     a, a
    ld      c, a

_swap:
; Eventually swaps 2 big integers based on the carry flag. Performs the swap in constant time to prevent timing attacks
; Inputs:
;    C = swap ? 0xFF : 0
;   DE = a
;   HL = b
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

_jumpHL:
    jp      (hl)

virtual at ti.cursorImage
_fmul:
; Performs a multiplication between two big integers, and returns the result in mod 2p. The pseudocode for multiplying
; looks like this:
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
; Inputs:
;   DE = out
;   BC = a mod 2p
;   HL = b mod 2p

; Copy the input variables to the temporary storage
    ld      (ix + mul.arg2), hl
    push    de
    push    bc
; Setup the product output
    ld      hl, _product
    ld      bc, INT_SIZE - 1
    ld      (hl), b
    ld      de, _product + 1
    ldir
; Also setup the other variables
    ld      (ix + mul.outerLoopCount), INT_SIZE
    pop     hl
    ld      de, _product
; Within a loop, get a single byte from a, and multiply it with the entirety of b, adding it to the product immediately
.mainLoop:
    ld      a, (hl)          ; a[index]
    inc     hl
    push    hl, de
    ld      iyh, a
    ld      hl, (ix + mul.arg2)
    xor     a, a            ; Reset carry + carry flag
repeat INT_SIZE
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
end repeat
; Add the last carry byte to the product. Since we work from low to high indexes, this last carry byte is guarenteed to
; not overlap with the previous product result, thus storing it directly works properly.
    adc     a, 0
    ld      (de), a
; Continue with the main loop
    pop     de, hl
    inc     de
    dec     (ix + mul.outerLoopCount)
    jp      nz, .mainLoop

; For the lower 32 bytes of the product, calculate sum(38 * product[i + 32]) and add to product directly
    ex      de, hl
    ld      de, _product
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
; Propagate the last carry byte back to the first falue and store to out directly
    adc     a, 0
    ld      c, a
    ld      b, 38
    mlt     bc
    ld      hl, _product
    pop     iy
    ld      de, (hl)
    ex      de, hl
    add     hl, bc
    ld      (iy), hl
    inc     de
    inc     de
    inc     de
    ld      bc, 0
repeat (INT_SIZE - 3) / 3
    lea     iy, iy + 3
    ex      de, hl
    ld      de, (hl)
    ex      de, hl
    adc     hl, bc
    ld      (iy), hl
    inc     de
    inc     de
    inc     de
end repeat
    ld      a, (de)
    adc     a, b
    ld      (iy + 3), a
    inc     de
    ld      a, (de)
    adc     a, b
    ld      (iy + 4), a
    ret

_faddInline:
; Performs an inline addition between two big integers mod 2p, and returns the result in the first num with mod 2p.
; Inputs:
;   DE = out, a mod 2p
;   HL = b mod 2p
    xor     a, a            ; Reset carry flag
repeat INT_SIZE
    ld      a, (de)         ; out[i] = a[i] + b[i] + carry
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
end repeat
    sbc     a, a
    and     a, 38           ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    add     a, (hl)
    ld      (hl), a
    ld      c, 0
    ld      b, INT_SIZE - 1
.subLoop:
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    djnz    .subLoop
    ret

_fsubInline:
; Performs an inline subtraction between two big integers mod 2p, and returns the result in the first num in mod 2p again.
; Inputs:
;   DE = out, a mod 2p
;   HL = b mod 2p
    xor     a, a            ; Reset carry flag
    ld      b, INT_SIZE
.subtractLoop:
    ld      a, (de)         ; out[i] = a[i] - b[i] - carry
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    djnz    .subtractLoop
; Now out is in the range (-2^255+19, 2^255-19). If the carry flag is set, the value is "negative", but we can easily
; calculate a mod 2p by subtracting 38 from the entire value, such that the output is always [0, 2p).
.normalize:
    sbc     a, a
    and     a, 38           ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    ld      c, a
    ld      a, (hl)
    sub     a, c
    ld      (hl), a
    ld      c, b
    ld      b, INT_SIZE - 1
.subLoop:
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    djnz    .subLoop
    ret

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
