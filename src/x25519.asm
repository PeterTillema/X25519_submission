INT_SIZE = 32
P_OFFSET = 19

    assume adl=1
    section .text

    public _custom_fmul
    public _tls_x25519_secret
    public _tls_x25519_publickey

macro fmul out, in1, in2
    ld      hl, in2
    push    hl
    if ~(in1 relativeto in2) | in1 <> in2
    ld      hl, in1
    end if
    push    hl
    ld      hl, out
    push    hl
    call    _fmul
    pop     hl, hl, hl
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

_tls_x25519_secret:
; Inputs:
;   (sp + 3) = shared_secret
;   (sp + 6) = my_private
;   (sp + 9) = their_public
;   (sp + 12) = yield_fn
;   (sp + 15) = yield_data
; Size: 988 bytes
; Timing: 489,421,971 cc = 10.196 s
    ld      iy, 0
    add     iy, sp
    ld      hl, (iy + 9)
    push    hl
    ld      hl, (iy + 6)
    push    hl
    ld      hl, (iy + 3)
    push    hl
    call    _scalarmult
    pop     hl, hl, hl
    ld      a, 1
    ret

_tls_x25519_publickey:
; Inputs:
;   (sp + 3) = public_key
;   (sp + 6) = private_key
;   (sp + 9) = yield_fn
;   (sp + 12) = yield_data
; Size: 988 bytes
; Timing: 489,421,971 cc = 10.196 s
    ld      iy, 0
    add     iy, sp
    ld      hl, _9
    push    hl
    ld      hl, (iy + 6)
    push    hl
    ld      hl, (iy + 3)
    push    hl
    call    _scalarmult
    pop     hl, hl, hl
    ld      a, 1
    ret

_scalarmult:
; Inputs:
;   (sp + 6) = out
;   (sp + 9) = scalar
;   (sp + 12) = point
scalar:
scalar.clampedPointer := 0                  ; A pointer to the current byte of scalar to check the bit against
scalar.clampedMask := 3                     ; A mask to check the scalar byte against. Rotates after the loop
scalar.mainLoopIndex := 4                   ; Main loop index
scalar.size := 5

    push    ix
    ld      ix, -scalar.size
    add     ix, sp
    ld      sp, ix
; Setup some variables
    ld      hl, _clamped + INT_SIZE - 1
    ld      (ix + scalar.clampedPointer), hl
    ld      a, 64
    ld      (ix + scalar.clampedMask), a
    ld      a, 255
    ld      (ix + scalar.mainLoopIndex), a
; Copy scalar to clamped, and edit byte 0 and byte 31
    ld      de, _clamped
    ld      hl, (ix + 9 + scalar.size)
    ld      a, (hl)
    and     a, 0xF8
    ld      (de), a
    inc     hl
    inc     de
    ld      bc, INT_SIZE - 1
    ldir
    dec     de
    ld      a, (de)
    and     a, 0x7F
    or      a, 0x40
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
    ld      hl, (ix + 12 + scalar.size)    ; Copy point to b
    ld      c, INT_SIZE
    ldir
    ld      (de), a         ; Clear c
    inc     de
    ld      hl, _c
    ld      c, INT_SIZE - 1
    ldir
    inc     a               ; d[0] = 1
    ld      (de), a
    inc     de
    dec     a
    ld      (de), a
    inc     de
    ld      c, INT_SIZE - 2 ; Clear _d
    ld      hl, _d + 1
    ldir
.mainLoop:
    ; Get bit
    ld      hl, (ix + scalar.clampedPointer)
    ld      a, (hl)
    and     a, (ix + scalar.clampedMask)
    sub     a, 1            ; Set -> cf is true; reset -> cf is false
    ccf
    push    af
    ld      de, _a          ; swap(a, b, bit)
    ld      hl, _b
    call    _swap
    pop     af
    push    af
    ld      de, _c          ; swap(c, d, bit)
    ld      hl, _d
    call    _swap
    pop     af
    push    af
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
    fmul _d, _b, (ix + 12 + scalar.size)
    fmul _b, _e, _e
; Final swaps
    pop     af
    push    af
    ld      de, _a          ; swap(a, b, bit)
    ld      hl, _b
    call    _swap
    pop     af
    ld      de, _c          ; swap(c, d, bit)
    ld      hl, _d
    call    _swap

; Get to the next bit
    ld      a, (ix + scalar.clampedMask)
    srl     a
    jr      nc, .continue
    ld      hl, (ix + scalar.clampedPointer)
    dec     hl
    ld      (ix + scalar.clampedPointer), hl
    ld      a, 128
.continue:
    ld      (ix + scalar.clampedMask), a
    dec     (ix + scalar.mainLoopIndex)
    jq      nz, .mainLoop
    ld      de, _b
    ld      hl, _c
    ld      bc, INT_SIZE
    ldir
    ld      b, 254
.inverseLoop:
    push    bc
    fmul _c, _c, _c
    pop     bc
    ld      a, b
    cp      a, 3
    jr      z, .continue2
    cp      a, 5
    jr      z, .continue2
    push    bc
    fmul _c, _c, _b
    pop     bc
.continue2:
    djnz    .inverseLoop
    fmul (ix + 6 + scalar.size), _a, _c
    lea     hl, ix + scalar.size
    ld      sp, hl
    pop     ix
    ret

_custom_fmul:
_fmul:
; Performs a multiplication between two big integers mod p, and returns the result in mod p again.
; It works because (a mod p) * (b mod p) = (a * b) mod p. The pseudocode for multiplying looks like this:
;  - Reset product outcome to zeroes
;  - For each byte in input a:
;    - Multiply with the entire value of b, and store to temp ([0,2^8-1] * [0,2^256-1] -> [0, 2^264-1], so it fits in 33 bytes)
;    - Add temp to the right offset to the product output, and add carry + zeroes for the remaining bytes in product
;  - Now product is a 64-byte value, i.e.:
;      product = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^256 + t_33 * 2^264 + ... + t_63 * 2^504
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^0 * (2p + 38) + t_33 * 2^1 * (2p + 38) + ... + t_63 * 2^248 * (2p + 38)
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 38 * 2^0 + t_33 * 38 * 2^1 + ... + t_63 * 38 * 2^248 (mod 2p)
;              = (t_0 + 38 * t_32) * 2^0 + ... + (t_30 + 38 * t_62) * 2^240 + (t_31 + 38 * t_63) * 2^248 (mod 2p)
;    That means that for each index in the lower 32 bytes, we can add 38*product[index + 32] and the result becomes mod 2p.
;  - We first calculate 38 times each byte in the second half of the product, and add them together. This gives a 33-byte value
;  - Add this result to the first 32 bytes of product
;  - The last byte from the intermediate result (the carry) will be propagated back, namely 38 * (value of last byte) will
;    be added to the first byte again. This can again trigger an overflow, so propagate the carry even further.
;  - The first 32 bytes of product now contains the output mod 2p, and will be copied to the out variable.
;  - Either out or out - p is used, like in the fadd routine.
; Inputs:
;   (sp + 3) = out
;   (sp + 6) = a mod p
;   (sp + 9) = b mod p
; Size: 213 bytes (D1C620 - D1C54B)
; Timing: 152,138 cc
mul:
mul.productOutputPointer := 0               ; A pointer to where the product output should be stored
mul.mainValuePointer := 3                   ; Pointer to the current byte of the main value
mul.outerLoopCount := 6                     ; Main count down
mul.size := 7

    push    ix
    ld      ix, -mul.size
    add     ix, sp
    ld      sp, ix
; First of all, setup the product output
    ld      hl, _product
    ld      (ix + mul.productOutputPointer), hl
    ld      (hl), 0
    ld      de, _product + 1
    ld      bc, INT_SIZE * 2 - 1
    ldir
; Also setup the other variables
    ld      (ix + mul.outerLoopCount), INT_SIZE
    ld      hl, (ix + 9 + mul.size)
    ld      (ix + mul.mainValuePointer), hl
; Within a loop, get a single byte from a, and multiply it with the entirety of b
.mainLoop:
    ld      hl, (ix + mul.mainValuePointer) ; hl -> a + index
    ld      a, (hl)                         ; hl -> a[index]
    inc     hl
    ld      (ix + mul.mainValuePointer), hl
    ld      iyh, a
    ld      iyl, INT_SIZE
    ld      de, _temp
    ld      hl, (ix + 12 + mul.size)
; Multiply a single byte with a 32-byte value. Multiply each byte with the single byte and add the carry from the
; previous product.
; In:
;  hl = b
;  de = out
;  iyh = num to multiply with
;  iyl = loop counter (32..0)
    xor     a, a            ; Reset carry + carry flag
.innerLoop1:
    ld      c, (hl)
    inc     hl
    ld      b, iyh
    mlt     bc
    adc     a, c
    ld      (de), a
    inc     de
    ld      a, b
    dec     iyl
    jr      nz, .innerLoop1
    ld      c, 0            ; Only used for the adc here and the adc within .addLoop2 (which is called many times, so a nice speedup)
    adc     a, c
    ld      (de), a
; If the calculation is done for a single byte, add the 33-byte value to the product output. The carry flag is always
; reset, as the "adc a, 0" never overflows. This is because a is the upper byte of b*c, which is at most FE, so adc is
; at most FF.
    ld      de, _temp
    ld      hl, (ix + mul.productOutputPointer)
    ld      b, INT_SIZE + 1
.addLoop1:
    ld      a, (de)
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .addLoop1
    ld      b, (ix + mul.outerLoopCount)
.addLoop2:
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    djnz    .addLoop2
; Continue with the main loop
    ld      hl, (ix + mul.productOutputPointer)
    inc     hl
    ld      (ix + mul.productOutputPointer), hl
    dec     (ix + mul.outerLoopCount)
    jr      nz, .mainLoop
; For the lower 32 bytes of the product, calculate sum(38 * product[i + 32]) and store to temp
    ld      de, _temp           ; HL now points to _product + INT_SIZE
    xor     a, a                ; Reset carry for the next calculations
    ld      iyl, INT_SIZE
.innerLoop2:
    ld      c, (hl)
    inc     hl
    ld      b, 38
    mlt     bc
    adc     a, c
    ld      (de), a
    inc     de
    ld      a, b
    dec     iyl
    jr      nz, .innerLoop2
    adc     a, 0                ; Make sure to also save the last carry byte
    ld      (de), a
; Add temp to product
    ld      de, _temp
    ld      hl, _product
    ld      b, INT_SIZE
.addLoop3:
    ld      a, (de)
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .addLoop3
; Propagate the last carry byte back to the first value
    ld      a, (de)
    ld      e, 0            ; Used for this adc and the next adc
    adc     a, e
    ld      c, a
    ld      b, 38
    mlt     bc
    ld      hl, _product
    ld      a, (hl)
    add     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      b, INT_SIZE - 2
.testloop:
    ld      a, (hl)
    adc     a, e
    ld      (hl), a
    inc     hl
    djnz    .testloop
; Copy temp to out
    ld      de, (ix + 6 + mul.size)
    ld      hl, _product
    ld      c, INT_SIZE
    ldir
    ld      de, (ix + 6 + mul.size)
; We don't need ix anymore, so pop in advance
    lea     hl, ix + mul.size
    ld      sp, hl
    pop     ix
; Perform the pack to calculate mod p instead of mod 2p
    ld      hl, _product
    jq      _calcModP

_fsub:
; Performs a subtraction between two big integers mod p, and returns the result in mod p again.
; It works because (a mod p) - (b mod p) = (a - b) mod p.
; Inputs:
;   DE = out
;   BC = a mod p
;   HL = b mod p
; Size: 49 bytes excluding jq
; Timing: 3302 excluding jq
    xor     a, a            ; Reset carry flag
    ld      iyl, INT_SIZE
.loop1:
    ld      a, (bc)         ; out[i] = a[i] - b[i] - carry
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    inc     bc
    dec     iyl
    jr      nz, .loop1
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
.loop3:
    inc     hl
    ld      a, (hl)
    adc     a, 0xFF
    ld      (hl), a
    djnz    .loop3
    inc     hl              ; Same as within the loop, but now 7F to not add the last bit
    ld      a, (hl)
    adc     a, 0x7F
    ld      (hl), a
    pop     hl              ; hl -> temp
    jq      _swap

_fadd:
; Performs an addition between two big integers mod p, and returns the result in mod p again.
; It works because (a mod p) + (b mod p) = (a + b) mod p.
; Inputs:
;   DE = out
;   BC = a mod p
;   HL = b mod p
; Size: 50 bytes
; Timing: 3306
    xor     a, a            ; Reset carry flag
    ld      iyl, INT_SIZE
.loop1:
    ld      a, (bc)         ; out[i] = a[i] + b[i] + carry
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    inc     bc
    dec     iyl
    jr      nz, .loop1
; Now out is in the range [0, 2p-2]. In order to do a mod p, we copy out to a temp variable, subtract p from
; that and eventually swap places (all in constant time), such that either out or (out - p) is used.
    dec     de
    ex      de, hl          ; hl -> out + 31
    ld      de, _temp + INT_SIZE - 1
    ld      bc, INT_SIZE
    lddr
    ex      de, hl
    inc     hl              ; hl -> temp
    inc     de              ; de -> out
_calcModP:
    push    hl
; Subtract p from temp (inline)
    ld      a, (hl)
    sub     a, -P_OFFSET
    ld      (hl), a
    ld      b, INT_SIZE - 2
.loop2:
    inc     hl
    ld      a, (hl)
    sbc     a, 0xFF
    ld      (hl), a
    djnz    .loop2
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
    ld      iyl, 32
.loop:
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
    jr      nz, .loop
    ret


repeat 1, x:$-_tls_x25519_publickey
    display `x, ' bytes'
end repeat

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
; Temporary usage
_temp:
    rb      INT_SIZE + 1


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
