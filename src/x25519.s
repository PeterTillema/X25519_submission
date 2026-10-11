.equ INT_SIZE, 32
.equ P_OFFSET, 19

; Code size: 553 bytes
; Relocation size: 1020 bytes
; Data size: 388 bytes (+ padding)
; Read only data size: 64 bytes

    .assume adl=1

.equ ti.cursorImage, 0E30800h

    .global _tls_x25519_secret
    .type   _tls_x25519_secret, @function
    .global _tls_x25519_publickey
    .type   _tls_x25519_publickey, @function

    .section .text

.equ arg1, 3
.equ arg2, 6
.equ arg3, 9
.equ arg4, 12
.equ sparg1, 6
.equ sparg2, 9
.equ sparg3, 12
.equ sparg4, 15
.equ sparg5, 18

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
.rept 5
    pop     hl
.endr
    ret

_tls_x25519_secret:
; Inputs:
;   arg1 = shared_secret (out)
;   arg2 = my_private (scalar)
;   arg3 = their_public (point)
;   arg4 = yield_fn
;   arg5 = yield_data
; Timing first attempt: 482,792,828 cc
; Timing current:       192,853,078 cc      ; Assuming yield_fn = NULL
tempVariables:
.equ tempVariables.mainLoopIndex, 0                   ; Main loop index
.equ tempVariables.arg2, 1

.equ tempVariables.size, 4

    push    ix
    ld      ix, -tempVariables.size
    add     ix, sp
    ld      sp, ix
; Relocate code to be more performant
    ld      hl, _x25519_reloc_load_start
    ld      de, _x25519_reloc_run_start
    ld      bc, _x25519_reloc_len
    ldir
; Copy point to actual point and edit byte 31
    ld      de, _point
    ld      hl, (ix + sparg3 + tempVariables.size)
    ld      c, INT_SIZE - 1
    ldir
    ld      a, (hl)
    and     a, 0x7F
    ld      (de), a
    inc     de
; Copy scalar to clamped, and edit byte 0 and byte 31
    ld      hl, (ix + sparg2 + tempVariables.size)
    ld      a, (hl)
    and     a, 0xF8
    ld      (de), a
    inc     hl
    inc     de
    ld      c, INT_SIZE - 2
    ldir
    ld      a, (hl)
    or      a, 0x40         ; and a, 0x7F is not necessary, as the last bit is not used at all
    add     a, a            ; Bit 7 is not used, so shift in advance
    ld      (de), a
    inc     de
; Fill _a to _d
    ld      a, 1            ; a[0] = 1
    ld      (de), a
    inc     de
    dec     a
    ld      (de), a
    inc     de              ; DE = _a + 2
    ld      c, INT_SIZE * 2 - 2 ; Clear _a and _c
    ld      hl, _a + 1
    ldir
    ld      hl, _point      ; Copy point to b
    ld      c, INT_SIZE
    ldir
    ld      hl, _a          ; _d = _a
    ld      c, INT_SIZE
    ldir
    ld      hl, _clamped + INT_SIZE - 1
    dec     b               ; b = loop index
    ld      c, 1 << 6       ; c = bit mask
    call    mainCalculationLoop

; Reject an all-zero shared secret (RFC 7748 §6.1. RFC 7748)
    ld      hl, (ix + sparg1 + tempVariables.size)
    ld      b, INT_SIZE
    xor     a, a
.checkNonzero:
    or      a, (hl)
    inc     hl
    djnz    .checkNonzero

    neg
    sbc     a, a
    and     a, 1
    
    lea     hl, ix + tempVariables.size
    ld      sp, hl
    pop     ix
    ret

mainCalculationLoop:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;; CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; A loops back from 255 to 1, so the current logic calls the yield_fn function after 128 loops (every ~2.25 seconds)
    push    bc
    sla     b
    jr      nz, .noYieldFn
    push    hl
    ld      hl, (ix + tempVariables.size + sparg4)
    add     hl, de
    or      a, a
    sbc     hl, de
    jr      z, .skipYieldFn
    ld      de, (ix + tempVariables.size + sparg5)
    push    de
    call    _jumpHL
    pop     de
.skipYieldFn:
    pop     hl
.noYieldFn:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;; /CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ; Get bit
    rlc     (hl)         ; hl -> clamped pointer
    push    hl
    sbc     a, a
    ld      c, a
    push    bc
; swap _a, _b
    ld      de, _a
    ld      hl, _b
    ld      iyh, INT_SIZE / 2 * 2
    call    _BigIntSwap
; fadd _e, _a, _c
    ex      de, hl              ; de -> _e
    ld      l, _a & 0xFF
    ld      bc, INT_SIZE
    ldir
    ld      e, _e & 0xFF      ; hl -> _c
    call    _BigIntAdd
; fsub _a, _a, _c
    ld      e, _a & 0xFF
    ld      l, _c & 0xFF
    call    _BigIntSub
; fadd _c, _b, _d
    ld      l, _b & 0xFF      ; de -> _c
    ld      c, INT_SIZE
    ldir
    ld      e, _c & 0xFF      ; hl -> _d
    call    _BigIntAdd
; fsub _b, _b, _d
    ld      l, _d & 0xFF      ; de -> _b
    call    _BigIntSub
; fsquare _d, _e
    ld      iy, _e              ; de -> _d
    ld      l, _e & 0xFF
    call    _BigIntMul.hl
; fsquare _f, _a
    ld      e, _f & 0xFF
    ld      iy, _a
    ld      l, _a & 0xFF
    call    _BigIntMul.hl
; fmul _a, _c, _a
    ld      iy, _c
    ld      e, _a & 0xFF
    ld      l, e
    call    _BigIntMul
; fmul _c, _b, _e
    ld      iy, _b
    ld      e, _c & 0xFF
    ld      l, _e & 0xFF
    call    _BigIntMul
; fadd _e, _a, _c
    ld      e, _e & 0xFF
    ld      l, _a & 0xFF
    ld      c, INT_SIZE
    ldir
    ld      e, _e & 0xFF      ; hl -> _c
    call    _BigIntAdd
; fsub _a, _a, _c
    ld      e, _a & 0xFF
    ld      l, _c & 0xFF
    call    _BigIntSub
; fsquare _b, _a
    ld      iy, _a
    ld      l, _a & 0xFF
    ld      e, _b & 0xFF
    call    _BigIntMul
; copy _d, _c
    ld      e, _c & 0xFF
    inc     hl                  ; hl -> _d
    ld      c, INT_SIZE
    ldir
; fsub _c, _c, _f
    ld      e, _c & 0xFF
    ld      l, _f & 0xFF
    call    _BigIntSub
; fmul _a, _c, _121665
    ld      iy, _c
    ld      e, _a & 0xFF
    ld      hl, _121665
    call    _BigIntMul
; fadd _a, _a, _d
    ld      e, _a & 0xFF
    ld      l, _d & 0xFF
    call    _BigIntAdd
; fmul _c, _c, _a
    ld      iy, _c              ; de -> _c
    ld      l, _a & 0xFF
    call    _BigIntMul
; fmul _a, _d, _f
    ld      iy, _d
    ld      e, _a & 0xFF
    ld      l, _f & 0xFF
    call    _BigIntMul
; fmul _d, _b, _point
    ld      iy, _b
    ld      e, _d & 0xFF
    ld      hl, _point
    call    _BigIntMul
; fsquare _b, _e
    ld      iy, _e
    ld      e, _b & 0xFF
    ld      l, _e & 0xFF
    call    _BigIntMul.hl
; swap _a, _b
    pop     bc
    ld      e, _a & 0xFF
    ld      l, _b & 0xFF
    ld      iyh, INT_SIZE / 2 * 2
    call    _BigIntSwap

; Get to the next bit
    pop     de              ; de -> clamped pointer
    pop     bc              ; b -> loop index, c -> mask
    rrc     c               ; loop through the bit mask
    sbc     hl, hl
    add     hl, de          ; hl -> clamped pointer, decremented if the carry flag was set
    dec     b
    jp      nz, mainCalculationLoop

; Copy _c to _b
    inc     d
    ld      e, _b & 0xFF
    inc     h
    ld      l, _c & 0xFF
    ld      c, INT_SIZE
    ldir

; Inverse _c
    ld      (ix + tempVariables.mainLoopIndex), 254
.inverseLoop:
; fsquare _c, _c
    ld      iy, _c
    ld      e, _c & 0xFF
    ld      l, e
    call    _BigIntMul.hl
    ld      a, (ix + tempVariables.mainLoopIndex)
    cp      a, 3
    jr      z, .continue2
    cp      a, 5
    jr      z, .continue2
; fmul _c, _c, _b
    ld      iy, _c
    ld      e, _c & 0xFF
    ld      l, _b & 0xFF
    call    _BigIntMul
.continue2:
    dec     (ix + tempVariables.mainLoopIndex)
    jr      nz, .inverseLoop

; Final multiplication, putting the result in out
; fmul (ix + sparg1 + tempVariables.size), _a, _c
    ld      de, (ix + sparg1 + tempVariables.size)
    ld      iy, _a
    ld      l, _c & 0xFF
    call    _BigIntMul
; Out is now in the range [0, 2^256), which is slightly more than 2p. Subtract p and swap if necessary. Repeat this step
; to account for the possible output in the range of [2p, 2^256).
    call    .normalizeModP
.normalizeModP:
    ld      hl, (ix + sparg1 + tempVariables.size)
; Perform the pack to calculate mod p instead of mod 2p
    ld      de, _product
; Subtract p from out and store to _product
    ld      a, (hl)
    sub     a, -P_OFFSET
    ld      (de), a
    ld      b, INT_SIZE - 2
    ld      c, -1
.subtractLoop:
; TODO: you can decide to unroll this loop a few times to have a small speed increase. However, that will only save ~800cc, while you add 150 bytes.
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
    sbc     a, a
    ld      bc, -INT_SIZE + 1
    add     hl, bc
    ex      de, hl
    add     hl, bc
    ld      c, a
    ld      iyh, INT_SIZE / 2
    jp      _BigIntSwap

_jumpHL:
    jp      (hl)

    .section .x25519.reloc, "ax", @progbits

_x25519_reloc_run_start:
_BigIntSwap:
; Eventually swaps 2 big integers based on the carry flag. Performs the swap in constant time to prevent timing attacks
; Inputs:
;    C = swap ? 0xFF : 0
;   DE = a
;   HL = b
;  IYH = loop count / 2
; Outputs:
;  BCU = ?
;    B = ?
;    C = swap ? 0xFF : 0
;   DE = a + INT_SIZE (+ INT_SIZE)
;   HL = b + INT_SIZE (+ INT_SIZE)

.swapLoop:
.rept 2
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
.endr
    dec     iyh
    jr      nz, .swapLoop
    ret

_BigIntMul:
; Performs a multiplication between two big integers, and returns the result in mod 2p. The pseudocode for multiplying
; looks like this:
;  - Reset first 32 bytes of product outcome to zeroes
;  - Apply the Karatsuba algorithm for multiplying the two input big integers.
;    Algorithm used from https://en.wikipedia.org/wiki/Karatsuba_algorithm#Basic_step:
;     Step 1: Clear 64 + 34 bytes of _product and _z3 with zeroes
;     Step 2: Multiply low(in1) with low(in2) and store to _product
;     Step 3: Multiply high(in1) with high(in2) and store to _product + 32
;     Step 4: Add low(in1) and high(in1) and store to _z3a
;     Step 5: Add low(in2) and high(in2) and store to _z3b
;     Step 6: Multiply _z3a and _z3b and store + add to _z3
;     Step 7: Subtract _product and _product + 32 from z3
;     Step 8: Add _z3 to _product + 16
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
;    B = 0
;   DE = out
;   IY = a mod 2p
;   HL = b mod 2p
; Outputs:
;   BC = 0
;   DE = _product + INT_SIZE * 2 - 1
;   HL = out + INT_SIZE - 1
_BigIntMul.iy:
    db      0xFD              ; ld (*), hl -> ld (*), iy
_BigIntMul.hl:
    ld      (.arg1), hl
    ld      (ix + tempVariables.arg2), hl
    push    de
; Setup the product and first part of z3 output
    ld      hl, _product
    ld      c, INT_SIZE / 2
    ld      (hl), b
    ld      de, _product + 1
    ldir
    ld      e, (_product + INT_SIZE) & 0xFF
    ld      l, _product & 0xFF
    ld      c, INT_SIZE / 2
    ldir
    inc     d
    ld      e, _z3 & 0xFF
    ld      l, _product & 0xFF
    ld      c, INT_SIZE / 2 + 1
    ldir
; Perform the first multiplication: low(in1) * low(in2)
    dec     d
    ld      e, _product & 0xFF
    ld      hl, (0 << 16) | (14 << 8) | 0x18        ; jr $+14
    ld      (_BigInt16Mul.jumpOffset), hl
    lea     hl, iy + 0
    ld      bc, (ix + tempVariables.arg2)
    call    _BigInt16Mul
; Perform the next multiplication: high(in1) * high(in2)
    ld      iy, (ix + tempVariables.arg2)
    lea     bc, iy + (INT_SIZE / 2)
    ld      e, (_product + INT_SIZE) & 0xFF
    call    _BigInt16Mul
; Add low(in1) and high(in1) and store to z3a
    inc     d
    ld      e, _z3a & 0xFF
.set .arg1, . + 2
    ld      iy, 0
    call    _BigIntAddLowHigh
; Add low(in2) to high(in2) and store to z3b
    inc     de
    ld      iy, (ix + tempVariables.arg2)
    call    _BigIntAddLowHigh
; Multiply z3a with z3b and store to z3
    ld      e, _z3 & 0xFF
    ld      hl, (0x4E << 16) | (0x44 << 8) | 0xFD   ; ld b, iyh \ ld c, (hl)
    ld      (_BigInt16Mul.jumpOffset), hl
    ld      hl, _BigInt16Mul.offset
    inc     (hl)
    ld      hl, _z3a
    ld      bc, _z3b
    ld      iyl, INT_SIZE / 2 + 1
    call    _BigInt16Mul.start
; Subtract _product from z3
    ld      hl, _BigInt16Mul.offset
    dec     (hl)
    ld      hl, _product
    call    _BigIntSubFromZ3
; Subtract _product + 32 from z3
    call    _BigIntSubFromZ3
; Add z3 to _product + 16
    dec     d
    ld      e, (_product + INT_SIZE / 2) & 0xFF
    ld      b, (INT_SIZE + 2) / 11
_BigIntMul.loop1:
.rept 11
    ld      a, (de)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
.endr
    djnz    _BigIntMul.loop1
    ld      a, (de)
    adc     a, (hl)
    ld      (de), a
    ld      c, b
    ld      b, 7
_BigIntMul.loop2:
.rept 2
    inc     de
    ld      a, (de)
    adc     a, c
    ld      (de), a
.endr
    djnz    _BigIntMul.loop2

; For the lower 32 bytes of the product, calculate sum(38 * product[i + 32]) and add to product + 32 directly
    dec     h
    ld      l, (_product + INT_SIZE) & 0xFF
    ld      e, _product & 0xFF
    xor     a, a
.addMul38Loop:
.irp i, 0,1,2,3
    ld      c, (hl)
    ld      b, 2 * P_OFFSET
    mlt     bc
    adc     a, c
    ld      c, a            ; Temporarily save a
    adc     a, b            ; b + cf -> b
    sub     a, c
    ld      b, a
    ld      a, (de)         ; Restore a and add (de) to (hl)
    add     a, c
    ld      (hl), a
    inc     de
    ld      a, b
.if \i != 3
    inc     hl
.endif
.endr
    inc     l               ; l = 0 -> stop, since then it's _product + INT_SIZE * 2 = XXXX00
    jr      nz, .addMul38Loop

; Propagate the last carry byte back to the first value and store to out directly
    adc     a, l
    ld      c, a
    ld      b, 2 * P_OFFSET
    mlt     bc
    ld      a, (de)
    add     a, c
    ld      c, l            ; c -> 0
    pop     hl              ; hl -> out, de -> _product + INT_SIZE
    ld      (hl), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, b
    ld      (hl), a
    ld      b, (INT_SIZE - 2) / 6
.addLoop:
.rept 6
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, c
    ld      (hl), a
.endr
    djnz    .addLoop
    ret

_BigIntAdd:
; Performs an inline addition between two big integers mod 2p, and returns the result in the first num with mod 2p.
; Inputs:
;   cf = reset
;   DE = out, a mod 2p
;   HL = b mod 2p
; Outputs:
;  BCU = untouched
;    B = 0
;    C = 0
;   DE = out + INT_SIZE
;   HL = out + INT_SIZE - 1

    ld      b, INT_SIZE / 8
.addLoop1:
.rept 8
    ld      a, (de)         ; out[i] = a[i] + b[i] + carry
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
.endr
    djnz    .addLoop1
    sbc     a, a
    and     a, 2 * P_OFFSET ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    add     a, (hl)
    ld      (hl), a
    ld      c, b
    ld      b, (INT_SIZE - 2) / 6
.addLoop2:
.rept 6
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
.endr
    djnz    .addLoop2
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    ret

_BigIntSub:
; Performs an inline subtraction between two big integers mod 2p, and returns the result in the first num in mod 2p again.
; Inputs:
;   cf = reset
;   DE = out, a mod 2p
;   HL = b mod 2p
; Outputs:
;  BCU = untouched
;    B = 0
;    C = 0
;   DE = out + INT_SIZE
;   HL = out + INT_SIZE - 1

    ld      b, INT_SIZE / 4
.subLoop1:
.rept 4
    ld      a, (de)         ; out[i] = a[i] - b[i] - carry
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
.endr
    djnz    .subLoop1

; Now out is in the range (-2^255+19, 2^255-19). If the carry flag is set, the value is "negative", but we can easily
; calculate a mod 2p by subtracting 38 from the entire value, such that the output is always [0, 2p).
    sbc     a, a
    and     a, 2 * P_OFFSET ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    ld      c, a
    ld      a, (hl)
    sub     a, c
    ld      (hl), a
    ld      c, b
    ld      b, (INT_SIZE - 2) / 6
.subLoop2:
.rept 6
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
.endr
    djnz    .subLoop2
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    ret

_BigIntAddLowHigh:
; Inputs:
;   IY = in
;   DE = out
; Outputs:
;   BC = in1 + 15
;   DE = in1 + 16
;   HL = in1 + 15
    lea     hl, iy + 0
    lea     bc, iy + 16
.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ld      a, (bc)
    adc     a, (hl)
    ld      (de), a
    inc     de
.if \i != 15
    inc     hl
    inc     bc
.endif
.endr
    sbc     a, a
    and     a, 1
    ld      (de), a
    ret

_BigIntSubFromZ3:
; Inputs:
;   HL = in2
; Outputs:
;    B = 0
;   DE = in1 + 34
;   HL = in1 + 32
    ld      e, _z3 & 0xFF
    ld      b, 2
_BigIntSubFromZ3.loop1:
.rept 16
    ld      a, (de)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
.endr
    djnz    _BigIntSubFromZ3.loop1
    ld      a, (de)
    sbc     a, b
    ld      (de), a
    inc     de
    ld      a, (de)
    sbc     a, b
    ld      (de), a
    ret

_BigInt16Mul:
; Calculates the product of 2 16-byte integers, resulting in a 32-byte integer
; Inputs:
;  IYL = count (16 or 17)
;   HL = in1
;   DE = out
;   BC = in2
; Outputs:
;   HL = in1 + count
;   DE = out + count
    ld      iyl, 16
_BigInt16Mul.start:
    ld      (.mul16Arg2SMC), bc
.mainLoop:

    ld      b, (hl)
    inc     hl
    push    hl
    ld      iyh, b
.set .mul16Arg2SMC, . + 1
    ld      hl, 0           ; hl -> in2
; First iteration
    ld      c, (hl)
    mlt     bc
    ld      a, (de)         ; Add c to (de)
    add     a, c
    ld      (de), a
    ld      a, b
    inc     de
    inc     hl
; Other iterations
_BigInt16Mul.jumpOffset = .             ; Replaces the first "ld b, iyh \ ld c, (hl)" with a "jr $+16 \ nop" in case of mul 16 instead of 17
.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ld      b, iyh
    ld      c, (hl)
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
.if \i != 15
    inc     hl
.endif
.endr
    adc     a, 0
    ld      (de), a
    ld      a, e
_BigInt16Mul.offset = . + 1
    sub     a, 15
    ld      e, a
    pop     hl
    dec     iyl
    jp      nz, .mainLoop
    ret
_x25519_reloc_run_end:

    .section .x25519.data, "aw", @progbits

; Duplicate of the input point, but with msb reset
_point:
    .space  INT_SIZE
; Used for scalar
_clamped:
    .space  INT_SIZE
_a:
    .space  INT_SIZE
_c:
    .space  INT_SIZE
_b:
    .space  INT_SIZE
_d:
    .space  INT_SIZE
_e:
    .space  INT_SIZE
_f:
    .space  INT_SIZE
; Used for multiplication
_product:
    .space  INT_SIZE * 2
_z3:
    .space  34
_z3a:
    .space  17
_z3b:
    .space  17

    .section .rodata

_9:
    .db     0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

_121665:
    .db     0x41, 0xDB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
