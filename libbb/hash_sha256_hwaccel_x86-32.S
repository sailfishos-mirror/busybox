#if ENABLE_SHA256_HWACCEL && defined(__GNUC__) && defined(__i386__)
/* The code is adapted from Linux kernel's source */

// We use shorter insns, even though they are for "wrong"
// data type (fp, not int).
// For Intel, there is no penalty for doing it at all
// (CPUs which do have such penalty do not support SHA insns).
// For AMD, the penalty is one extra cycle
// (allegedly: I failed to find measurable difference).

//#define mova128 movdqa
#define mova128 movaps
//#define movu128 movdqu
#define movu128 movups
//#define shuf128_32 pshufd
#define shuf128_32 shufps

// pshufb and palignr are SSSE3 insns.
// We do not check SSSE3 in cpuid,
// all SHA-capable CPUs support it as well.

#ifdef __linux__
	.section	.note.GNU-stack, "", @progbits
#endif
	.section	.text.sha256_process_block64_shaNI, "ax", @progbits
	.globl	sha256_process_block64_shaNI
	.hidden	sha256_process_block64_shaNI
	.type	sha256_process_block64_shaNI, @function

#define DATA_PTR	%eax

#define SHA256CONSTANTS	%ecx

#define MSG		%xmm0
#define STATE0		%xmm1
#define STATE1		%xmm2
#define MSG0		%xmm3
#define MSG1		%xmm4
#define MSG2		%xmm5
#define MSG3		%xmm6

#define XMMTMP		%xmm7

#define SHUF(a,b,c,d) $((a)+((b)<<2)+((c)<<4)+((d)<<6))

	.balign	8	# allow decoders to fetch at least 2 first insns
sha256_process_block64_shaNI:

	movu128		76+0*16(%eax), XMMTMP /* ABCD (shown least-significant-dword-first) */
	movu128		76+1*16(%eax), STATE1 /* EFGH */
/* shufps: dwords 0,1 of the result are selected from *2nd* operand, and dwords 2,3 from 1st operand */
	mova128		STATE1, STATE0
	/* ---		-------------- ABCD -- EFGH */
	shufps		SHUF(1,0,1,0), XMMTMP, STATE0 /* FEBA */
	shufps		SHUF(3,2,3,2), XMMTMP, STATE1 /* HGDC */

/* XMMTMP holds flip mask from here... */
	mova128		PSHUFFLE_BSWAP32_FLIP_MASK, XMMTMP
	movl		$K256+8*16, SHA256CONSTANTS

// sha256rnds2 instruction uses only lower 64 bits of MSG.
// The code below needs to move upper 64 bits to lower 64 bits
// for the second sha256rnds2 invocation
// (what remains in upper bits does not matter).
// There are several ways to do it:
// movhlps    MSG, MSG                // abcd -> cdcd (3 bytes of code)
// shuf128_32 SHUF(2,3,n,n), MSG, MSG // abcd -> cdXX (4 bytes)
// punpckhqdq MSG, MSG                // abcd -> cdcd (4 bytes)
// unpckhpd   MSG, MSG                // abcd -> cdcd (4 bytes)
// psrldq     $8, MSG                 // abcd -> cd00 (5 bytes)
// palignr    $8, MSG, MSG            // abcd -> cdab (6 bytes, SSSE3 insn)
#define MOVE_UPPER64_DOWN(reg) movhlps reg, reg
//#define MOVE_UPPER64_DOWN(reg) shuf128_32 SHUF(2,3,0,0), reg, reg
//#define MOVE_UPPER64_DOWN(reg) punpckhqdq reg, reg
//#define MOVE_UPPER64_DOWN(reg) unpckhpd reg, reg
//#define MOVE_UPPER64_DOWN(reg) psrldq $8, reg
//#define MOVE_UPPER64_DOWN(reg) palignr $8, reg, reg

	/* Rounds 0-3 */
	movu128		0*16(DATA_PTR), MSG
	pshufb		XMMTMP, MSG
	mova128		MSG, MSG0
		paddd		0*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0

	/* Rounds 4-7 */
	movu128		1*16(DATA_PTR), MSG
	pshufb		XMMTMP, MSG
	mova128		MSG, MSG1
		paddd		1*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG1, MSG0

	/* Rounds 8-11 */
	movu128		2*16(DATA_PTR), MSG
	pshufb		XMMTMP, MSG
	mova128		MSG, MSG2
		paddd		2*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG2, MSG1

	/* Rounds 12-15 */
	movu128		3*16(DATA_PTR), MSG
	pshufb		XMMTMP, MSG
/* ...to here */
	mova128		MSG, MSG3
		paddd		3*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG3, XMMTMP
	palignr		$4, MSG2, XMMTMP
	paddd		XMMTMP, MSG0
	sha256msg2	MSG3, MSG0
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG3, MSG2

	/* Rounds 16-19 */
	mova128		MSG0, MSG
		paddd		4*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG0, XMMTMP
	palignr		$4, MSG3, XMMTMP
	paddd		XMMTMP, MSG1
	sha256msg2	MSG0, MSG1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG0, MSG3

	/* Rounds 20-23 */
	mova128		MSG1, MSG
		paddd		5*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG1, XMMTMP
	palignr		$4, MSG0, XMMTMP
	paddd		XMMTMP, MSG2
	sha256msg2	MSG1, MSG2
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG1, MSG0

	/* Rounds 24-27 */
	mova128		MSG2, MSG
		paddd		6*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG2, XMMTMP
	palignr		$4, MSG1, XMMTMP
	paddd		XMMTMP, MSG3
	sha256msg2	MSG2, MSG3
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG2, MSG1

	/* Rounds 28-31 */
	mova128		MSG3, MSG
		paddd		7*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG3, XMMTMP
	palignr		$4, MSG2, XMMTMP
	paddd		XMMTMP, MSG0
	sha256msg2	MSG3, MSG0
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG3, MSG2

	/* Rounds 32-35 */
	mova128		MSG0, MSG
		paddd		8*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG0, XMMTMP
	palignr		$4, MSG3, XMMTMP
	paddd		XMMTMP, MSG1
	sha256msg2	MSG0, MSG1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG0, MSG3

	/* Rounds 36-39 */
	mova128		MSG1, MSG
		paddd		9*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG1, XMMTMP
	palignr		$4, MSG0, XMMTMP
	paddd		XMMTMP, MSG2
	sha256msg2	MSG1, MSG2
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG1, MSG0

	/* Rounds 40-43 */
	mova128		MSG2, MSG
		paddd		10*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG2, XMMTMP
	palignr		$4, MSG1, XMMTMP
	paddd		XMMTMP, MSG3
	sha256msg2	MSG2, MSG3
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG2, MSG1

	/* Rounds 44-47 */
	mova128		MSG3, MSG
		paddd		11*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG3, XMMTMP
	palignr		$4, MSG2, XMMTMP
	paddd		XMMTMP, MSG0
	sha256msg2	MSG3, MSG0
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG3, MSG2

	/* Rounds 48-51 */
	mova128		MSG0, MSG
		paddd		12*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG0, XMMTMP
	palignr		$4, MSG3, XMMTMP
	paddd		XMMTMP, MSG1
	sha256msg2	MSG0, MSG1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0
	sha256msg1	MSG0, MSG3

	/* Rounds 52-55 */
	mova128		MSG1, MSG
		paddd		13*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG1, XMMTMP
	palignr		$4, MSG0, XMMTMP
	paddd		XMMTMP, MSG2
	sha256msg2	MSG1, MSG2
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0

	/* Rounds 56-59 */
	mova128		MSG2, MSG
		paddd		14*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
	mova128		MSG2, XMMTMP
	palignr		$4, MSG1, XMMTMP
	paddd		XMMTMP, MSG3
	sha256msg2	MSG2, MSG3
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0

	/* Rounds 60-63 */
	mova128		MSG3, MSG
		paddd		15*16-8*16(SHA256CONSTANTS), MSG
		sha256rnds2	MSG, STATE0, STATE1
		MOVE_UPPER64_DOWN(MSG)
		sha256rnds2	MSG, STATE1, STATE0

	/* Write hash values back in the correct order */
	mova128		STATE0, XMMTMP
/* shufps: dwords 0,1 of the result are selected from *2nd* operand, and dwords 2,3 from 1st operand */
	/* ---		-------------- HGDC -- FEBA */
	shufps		SHUF(3,2,3,2), STATE1, STATE0 /* ABCD */
	shufps		SHUF(1,0,1,0), STATE1, XMMTMP /* EFGH */
	/* add current hash values to previous ones */
	movu128		76+1*16(%eax), STATE1
	paddd		XMMTMP, STATE1
	movu128		STATE1, 76+1*16(%eax)
	movu128		76+0*16(%eax), XMMTMP
	paddd		XMMTMP, STATE0
	movu128		STATE0, 76+0*16(%eax)

	ret
	.size	sha256_process_block64_shaNI, .-sha256_process_block64_shaNI

	.section	.rodata.cst256.K256, "aM", @progbits, 256
	.balign	16
K256:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

	.section	.rodata.cst16.PSHUFFLE_BSWAP32_FLIP_MASK, "aM", @progbits, 16
	.balign	16
PSHUFFLE_BSWAP32_FLIP_MASK:
	.octa	0x0c0d0e0f08090a0b0405060700010203

#endif
