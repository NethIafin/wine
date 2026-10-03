/*
 * OpenBSD patcher for %gs calls
 *
 * Copyright (C) 2026 Andrii Yukhymchak
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#if defined(__OpenBSD__)

#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "unix_private.h"
#include "gs_openbsd.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

long teb_tls_offset;

/***********************************************************************
 *           gs_init_process
 * Initializes and checks __wine_teb_tls_offset for a thread
 */
void gs_init_process(void)
{
    long (*get_offset)(void) = dlsym( RTLD_DEFAULT, "__wine_teb_tls_offset" );

    if (!get_offset)
    {
        ERR( "__wine_teb_tls_offset not found. Old loader?\n");
        exit(1);
    }
    teb_tls_offset = get_offset();

    if((int)teb_tls_offset != teb_tls_offset || (int)(teb_tls_offset + 8) != teb_tls_offset + 8)
    {
        ERR( "TEB TLS offset %lx is out of range\n", teb_tls_offset);
        exit(1);
    }
}

/***********************************************************************
 *           gs_set_thread_teb
 */
void gs_set_thread_teb( TEB *teb )
{
    __asm__ volatile( "movq %0, %%fs:(%1)" :: "r" (teb), "r" (teb_tls_offset) : "memory" );
}


/* Instruction decoding helpers.
 *
 * There is a way to attach an instruction decoder library, but since all that we need is just if there is %gs prefix
 * understand which register we want to pick, and the length of command, we can limit ourselves to just few hundred lines of decoder
 * instead of thousands and thousands of lines for a full decompiler
 */

/* Intel register numbers for ModRM and SIB (8-15 regs need a REX bit) */
enum { GS_RAX, GS_RCX, GS_RDX, GS_RBX, GS_RSP, GS_RBP, GS_RSI, GS_RDI };

/* instructions accepted in front of %gs accessor */
#define PREFIX_OPSIZE       0x66    /* operand size override: 16-bit operands */
#define PREFIX_LOCK         0xf0    /* lock prefix */

/* GS and FS - what we search for and what we replace with */
#define PREFIX_GS           0x65
#define PREFIX_FS           0x64

/* REX prefix and its bits: 0100WRXB */
#define REX_BASE            0x40    /* REX marker bit */
#define REX_W               0x08    /* 64-bit operand size */
#define REX_R               0x04    /* ModRM.reg += 8 */
#define REX_X               0x02    /* SIB.index += 8 */
#define REX_B               0x01    /* ModRM.rm or SIB.base += 8 */

/* ModRM byte: ddrrrmmm - mod-reg-rm */
#define MODRM(mod,reg,rm)   (((mod) << 6) | (((reg) & 7) << 3) | ((rm) & 7)) /* build ModRM from segments */
#define MODRM_RM_SIB        4       /* if ModRM.rm = 100 then SIB byte follows */
#define MODRM_RM_DISP       5       /* if ModRM.rm = 101 AND mod = 00 then %rip-relative */

/* SIB byte: ssiiibbb - scale-index-base */
#define SIB(scale,index,base) (((scale) << 6) | (((index) & 7) << 3) | ((base) & 7)) /* build SIB from segments */
#define SIB_NO_INDEX        4       /* if SIB.index = 100 without REX.X - no index */
#define SIB_NO_BASE         5       /* if SIB.base  = 101 with mod = 00 then no base and disp32 follows */
#define SIB_ABSOLUTE        SIB ( 0, SIB_NO_INDEX, SIB_NO_BASE ) /* just disp32 */

/* Opcode defines, so instead of magic constants we have some understanding what's being added */
#define OPCODE_ESCAPE       0x0f    /* first byte of two-byte opcode kept as 0x100 | second byte */
#define JMP_REL32           0xe9    /* used to replace the command and then jump back from the stub */
#define JMP_REL32_LEN       5       /* length of JMP_REL32 - e9 and 32 bits of rel jump offset */
#define INT3                0xcc    /* we are using int3 to pad our codestubs and source of our jumps to trap any stray jumps */
#define MAX_INSN_LEN        15      /* longest possible x86-64 instruction */
#define IMM_Z               0xff

/* decoded %gs instruction and its information */
struct gs_insn
{
    BYTE                    bytes[MAX_INSN_LEN];        /* full instruction as it is */
    unsigned int            len;                        /* length of the instruction */
    BYTE                    seg;                        /* segment prefix - GS (to be rewritten) or FS (already rewrote it) */
    unsigned int            seg_pos;                    /* gs/fs segment location */
    BYTE                    rex;                        /* REX prefix, 0 if no rex prefix */
    unsigned int            rex_pos;                    /* where REX prefix is located, or where opcode is if no rex */
    unsigned int            opcode;                     /* opcode 0x100 | xx for 0f xx */
    unsigned int            opcode_pos;                 /* location of the first opcode byte */
    LONG64                  disp;                       /* displacement, or moffs address */
    unsigned int            disp_pos;                   /* position of the displacement */
    unsigned int            disp_len;                   /* size of the displacement - 0, 1, 4, or 8 (moffs) */
    unsigned int            imm_pos;                    /* position of the immediate */
    unsigned int            imm_len;                    /* size of the immediate - 0, 1, 2, 4 */
    unsigned int            size;                       /* bytes of memory accessed */
    unsigned int            ext;                        /* ModRM.reg field (opcode extension for group opcodes) */
    int                     reg;                        /* register operand or -1 if none */
    int                     base;                       /* base register or -1 if none */
    int                     index;                      /* index register or -1 if none */
    unsigned int            scale;                      /* index is shifted left by this */
    BOOL                    high_byte;                  /* reg 4-7 are %ah %ch %dh %bh */
    BOOL                    moffs;                      /* a0-a3 form: 64 bit absolute addr without ModRM */
    BOOL                    read_only;                  /* does not affect memory */
};

/***********************************************************************
 *           get_gs_reg
 * converts register index into pointer in the signal context
 */
static ULONG64 *get_gs_reg( ucontext_t *ucontext, unsigned int reg )
{
    switch (reg)
    {
    case 0: return (ULONG64 *)&ucontext->sc_rax;
    case 1: return (ULONG64 *)&ucontext->sc_rcx;
    case 2: return (ULONG64 *)&ucontext->sc_rdx;
    case 3: return (ULONG64 *)&ucontext->sc_rbx;
    case 4: return (ULONG64 *)&ucontext->sc_rsp;
    case 5: return (ULONG64 *)&ucontext->sc_rbp;
    case 6: return (ULONG64 *)&ucontext->sc_rsi;
    case 7: return (ULONG64 *)&ucontext->sc_rdi;
    case 8: return (ULONG64 *)&ucontext->sc_r8;
    case 9: return (ULONG64 *)&ucontext->sc_r9;
    case 10: return (ULONG64 *)&ucontext->sc_r10;
    case 11: return (ULONG64 *)&ucontext->sc_r11;
    case 12: return (ULONG64 *)&ucontext->sc_r12;
    case 13: return (ULONG64 *)&ucontext->sc_r13;
    case 14: return (ULONG64 *)&ucontext->sc_r14;
    case 15: return (ULONG64 *)&ucontext->sc_r15;
    default: ERR( "register with index %d does not exist\n", reg );
        return NULL;
    }
}

/***********************************************************************
 *           get_gs_opcode_info
 * builds opcode info. insn->opcode, insn->ext and insn->rex expected to be already set
 * This method fills out what those opcodes imply
 */
static BOOL get_gs_opcode_info( struct gs_insn *insn, BOOL *reg_operand, BOOL *byte_op,
                               unsigned int *mem_size, unsigned int *imm )
{
    unsigned int op = insn->opcode;
    unsigned int ext = insn->ext;

    /* most common states */
    *reg_operand = TRUE;    /* ModRM.reg is a register, not an opcode */
    *byte_op     = FALSE;   /* 8-bit operands */
    *mem_size    = 0;       /* memory operand size if not the operand size */
    *imm         = 0;
    insn->read_only = FALSE;

    /* add, or, adc, sbb, and, sub, xor, cmp with a register: 00ooodw
     * ooo - the operation, and 111 is cmp
     * d - 1 if register is the destination
     * w - 0 for bytes
     */
    if (op < 0x40 && (op & 7) < 4)
    {
        *byte_op = !(op & 1);
        insn->read_only = (op & 2) || (op >> 3) == 7;
        return TRUE;
    }

    /* other cases */
    switch (op)
    {
        case 0x63: /* movsxd r/m32, r64 */
            *mem_size = 4;
            insn->read_only = TRUE;
            return TRUE;
        /* group 1 ([add, or, adc, sbb, and, sub, xor, cmp] via ext) */
        case 0x80: /* r/m8, imm8 */
            *reg_operand = FALSE;
            *byte_op = TRUE;
            *imm = 1;
            insn->read_only = (ext == 7); /* cmp */
            return TRUE;
        case 0x81: /* r/m, imm16/32 */
            *reg_operand = FALSE;
            *imm = IMM_Z;
            insn->read_only = (ext == 7); /* cmp */
            return TRUE;
        case 0x83: /* r/m, imm8 (sign-extended) */
            *reg_operand = FALSE;
            *imm = 1;
            insn->read_only = (ext == 7); /* cmp */
            return TRUE;
        /* end of group 1 */
        case 0x84: /* test r8, r/m8 */
            *byte_op = TRUE;
            insn->read_only = TRUE;
            return TRUE;
        case 0x85: /* test r, r/m */
            insn->read_only = TRUE;
            return TRUE;
        case 0x88: /* mov r8, r/m8 */
            *byte_op = TRUE;
            return TRUE;
        case 0x89: /* mov r, r/m */
            return TRUE;
        case 0x8a: /* mov r/m8, r8 */
            *byte_op = TRUE;
            insn->read_only = TRUE;
            return TRUE;
        case 0x8b: /* mov r/m, r */
            insn->read_only = TRUE;
            return TRUE;
        /* ext picks the instruction, we only support those we can stub */
        case 0xc6: /* mov imm8, r/m8  , only ext = 0 is defined behavior */
            if (ext) return FALSE;
            *reg_operand = FALSE;
            *byte_op = TRUE;
            *imm = 1;
            return TRUE;
        case 0xc7: /* mov imm16/32, r/m , only ext = 0 is defined behavior */
            if (ext) return FALSE;
            *reg_operand = FALSE;
            *imm = IMM_Z;
            return TRUE;
        case 0xf6: /* group 3 r/m8: only test imm8 is allowed to be stubbed - ext = 0 */
            if (ext) return FALSE;
            *reg_operand = FALSE;
            *byte_op = TRUE;
            *imm = 1;
            insn->read_only = TRUE;
            return TRUE;
        case 0xf7: /* group 3 r/m: only test imm16/32 is allowed to be stubbed - ext = 0 */
            if (ext) return FALSE;
            *reg_operand = FALSE;
            *imm = IMM_Z;
            insn->read_only = TRUE;
            return TRUE;
        case 0xfe: /* group 4 r/m8: exts - 0 (inc) and 1 (dec), rest is undefined */
            if (ext > 1) return FALSE;
            *reg_operand = FALSE;
            *byte_op = TRUE;
            return TRUE;
        case 0xff: /* group 5 r/m: exts - 0 (inc) and 1 (dec), rest is call/jmp/push - dangerous to stub */
            if (ext > 1) return FALSE;
            *reg_operand = FALSE;
            return TRUE;
        /* end of ext cases */
        case 0x1b6: /* movzx r/m8, r */
        case 0x1be: /* movsx r/m8, r */
            *mem_size = 1;
            insn->read_only = TRUE;
            return TRUE;
        case 0x1b7: /* movzx r/m16, r */
        case 0x1bf: /* movsx r/m16, r */
            *mem_size = 2;
            insn->read_only = TRUE;
            return TRUE;
        /* cmovcc group */
        case 0x140: case 0x141: case 0x142: case 0x143:
        case 0x144: case 0x145: case 0x146: case 0x147:
        case 0x148: case 0x149: case 0x14a: case 0x14b:
        case 0x14c: case 0x14d: case 0x14e: case 0x14f:
            insn->read_only = TRUE;
            return TRUE;
        default:
            return FALSE;
    }
}

/***********************************************************************
 *           decode_gs_insn
 * fully decodes an instruction with %gs or %fs memory operand:
 *
 * should be of form
 * [prefixes] [REX] opcode ModRM [SIB] [disp8/disp32] [imm]
 * [prefixes] [REX] a0-a3 moffs64
 *
 * bytes[0..avail) are the bytes readable at the instruction
 */

static BOOL decode_gs_insn( struct gs_insn *insn, const BYTE *bytes, unsigned int avail )
{
    unsigned int i, modrm, mod, rm, sib, rex_w, rex_r, rex_x, rex_b;
    /* some common defaults */
    unsigned int mem_size = 0;
    unsigned int imm = 0;
    BOOL opsize = FALSE;
    BOOL byte_op = FALSE;
    BOOL reg_operand = TRUE;

    /* store instruction bytes */
    memset( insn, 0, sizeof(*insn));
    avail = min( avail, MAX_INSN_LEN );
    memcpy( insn->bytes, bytes, avail );

    /* prefixes in any order */
    for (i = 0; ; i++)
    {
        if (i >= avail) return FALSE; /* all prefixes? bad pointer/command */
        if (bytes[i] == PREFIX_GS || bytes[i] == PREFIX_FS)
        {
            if (insn->seg) return FALSE; /* two segment prefixes */
            insn->seg = bytes[i];
            insn->seg_pos = i;
        }
        else if (bytes[i] == PREFIX_OPSIZE) opsize = TRUE;
        else if (bytes[i] != PREFIX_LOCK) break; /* found end of prefixes */
    }
    if (!insn->seg) return FALSE; /* not an FS/GS command */
    insn->rex_pos = i;

    /* REX must come right before opcode bytes */
    if ((bytes[i] & 0xf0) == REX_BASE) insn->rex = bytes[i++];
    rex_w = insn->rex & REX_W ? 8 : 0;
    rex_r = insn->rex & REX_R ? 8 : 0;
    rex_x = insn->rex & REX_X ? 8 : 0;
    rex_b = insn->rex & REX_B ? 8 : 0;

    /* check if we escaped allowed size. Bad pointer/command? */
    if (i >= avail) return FALSE;

    insn->opcode_pos = i;
    insn->opcode = bytes[i++];

    /* 2byte opcodes */
    if (insn->opcode == OPCODE_ESCAPE)
    {
        /* check if we escaped allowed size. Bad pointer/command? */
        if (i >= avail) return FALSE;

        insn->opcode = 0x100 | bytes[i++];
    }

    /* [prefixes] [REX] a0-a3 moffs64 cases
     * mov moffs, %al
     * mov moffs, %eax
     * mov %al, moffs
     * mov %eax moffs
     */
    if(insn->opcode >= 0xa0 && insn->opcode <= 0xa3)
    {
        /* check if we escaped allowed size. Bad pointer/command? */
        if (i + 8 > avail) return FALSE;
        insn->moffs = TRUE;
        insn->reg = GS_RAX;
        insn->base = insn->index = -1;
        insn->disp_pos = i;
        insn->disp_len = 8;
        memcpy( &insn->disp, bytes + i, 8 ); /* copy moffs */
        i += 8;
        byte_op = !(insn->opcode & 1);
        insn->read_only = (insn->opcode <= 0xa1);
    }
    /* other cases */
    else
    {
        /* check if we escaped allowed size. Bad pointer/command? */
        if (i >= avail) return FALSE;
        modrm = bytes[i++];
        mod = modrm >> 6;
        insn->ext = (modrm >> 3) & 7;
        rm = modrm & 7;
        if (mod == 3) return FALSE; /* a register, not a memory. Should never fault on %gs */

        /* get/check remaining gs info */
        if (!get_gs_opcode_info( insn, &reg_operand, &byte_op, &mem_size, &imm )) return FALSE;

        insn->reg = reg_operand ? (int)(insn->ext | rex_r) : -1;

        if (rm == MODRM_RM_SIB)
        {
            if (i + 1 > avail) return FALSE;
            sib = bytes[i++];
            insn->scale = sib >> 6;
            insn->index = ((sib >> 3) & 7) | rex_x;
            if (insn->index == SIB_NO_INDEX) insn->index = -1; /* 100 means no index reg, 1100 is %r12 */
            insn->base = (sib & 7) | rex_b;
            if ((sib & 7) == SIB_NO_BASE && mod == 0) /* no base reg even with REX_B, it is disp32 instead */
            {
                insn->base = -1;
                mod = 2;
            }
            /* don't you just love all those special cases? Thanks x86-64 */
        }
        else if (rm == MODRM_RM_DISP && mod == 0) return FALSE; /* %rip-relateive, not a TEB */
        else
        {
            insn->base = rm | rex_b;
            insn->index = -1;
        }

        insn->disp_pos = i;
        if (mod == 1) /* disp8, sign extended */
        {
            if (i + 1 > avail) return FALSE;
            insn->disp = (signed char) bytes[i];
            insn->disp_len = 1;
        }
        else if (mod == 2) /* disp32, sign extneded */
        {
            int disp;
            if (i + 4 > avail) return FALSE;
            memcpy( &disp, bytes + i, 4 );
            insn->disp = disp;
            insn->disp_len = 4;
        }

        i += insn->disp_len;
    }

    /* the immediate - size depends on the operand size */
    if (imm == IMM_Z) imm = (opsize && !rex_w) ? 2 : 4;
    insn->imm_pos = i;
    insn->imm_len = imm;
    i += imm;

    /* final boundary check */
    if (i > avail) return FALSE;
    insn->len = i;

    /* bytes accessed - 8-bit or a fixed size or the operand size. Keep REX.W in mind */
    if (byte_op) insn->size = 1;
    else if (mem_size) insn->size = mem_size;
    else insn->size = rex_w ? rex_w : opsize ? 2 : 4;

    /* without any rex prefix, 4-7 byte registers are %ah %ch %dh %bh */
    insn->high_byte = byte_op && !insn->rex && insn->reg >= 4 && insn->reg <= 7;

    /* success */
    return TRUE;
}


#endif /* defined(__OpenBSD__)*/
