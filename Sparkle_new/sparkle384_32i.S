///////////////////////////////////////////////////////////////////////////////
// sparkle384s_32i.S: Size-optimized RV32I implementation of SPARKLE384.     //
// This file is part of the SPARKLE submission to NIST's LW Crypto Project.  //
// Version 1.1.2 (2020-10-30), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019-2020 University of Luxembourg <http://www.uni.lu/>.    //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY/ without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////


.section .text
.balign 4


.global sparkle384_rv32


///////////////////////////////////////////////////////////////////////////////
//////////////////////// REGISTER NAMES AND CONSTANTS /////////////////////////
///////////////////////////////////////////////////////////////////////////////

// register sptr holds the start address of array `state`
#define sptr a0
// register step holds the number of steps (parameter `steps`)
#define step a1
// registers x0w to y5w hold 12 words from array `state`
#define x0w a2
#define y0w a3
#define x1w a4
#define y1w a5
#define x2w a6
#define y2w a7
#define x3w t0
#define y3w t1
#define x4w t2
#define y4w t3
#define x5w t4
#define y5w t5
// register txy holds the temporary values tx and ty
#define txy t6
// registers c0w to c5w hold round constants from array `rcon`
#define c0w s1
#define c1w s2
#define c2w s3
#define c3w s4
#define c4w s5
#define c5w s6
// register cptr holds the start address of array `rcon`
#define cptr s7
// register cnt holds the step counter (for loop termination)
#define cnt s8
// register trr serves as temporary register for rotations
#define trr s9


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// MACROS FOR SPARKLE384 ////////////////////////////
///////////////////////////////////////////////////////////////////////////////


.macro PROLOGUE_384
    // allocate space on stack
    addi    sp, sp, -36  // add to sp -36 and saves it in sp 
    // push nine callee-saved registers
    sw      s1, 0(sp)   //Store Word (SW) instruction, stores 32-bit values from a register to memory. stores s1 in sp+offset
    sw      s2, 4(sp)
    sw      s3, 8(sp)
    sw      s4, 12(sp)
    sw      s5, 16(sp)
    sw      s6, 20(sp)
    sw      s7, 24(sp)
    sw      s8, 28(sp)
    sw      s9, 32(sp)
    // load the 12 state-words x0-y5
    lw      x0w, 0(sptr)// The Load Word (LW) instruction, moves a word, 32-bit value, from memory to register. The instruction is used for signed values
    lw      y0w, 4(sptr)// lw y0w, 4(sptr) # y0w ←− valueAt[sptr + 4]
    lw      x1w, 8(sptr)
    lw      y1w, 12(sptr)
    lw      x2w, 16(sptr)
    lw      y2w, 20(sptr)
    lw      x3w, 24(sptr)
    lw      y3w, 28(sptr)
    lw      x4w, 32(sptr)
    lw      y4w, 36(sptr)
    lw      x5w, 40(sptr)
    lw      y5w, 44(sptr)
    // load the 6 round constants c0-c5
    la      cptr, RCON  // The Load Address (LA) loads the location address of the specified SYMBOL 
    lw      c0w, 0(cptr)
    lw      c1w, 4(cptr)
    lw      c2w, 8(cptr)
    lw      c3w, 12(cptr)
    lw      c4w, 16(cptr)
    lw      c5w, 20(cptr)
.endm


.macro EPILOGUE_384
    // store the 12 state-words x0-y5
    sw      x0w, 0(sptr)
    sw      y0w, 4(sptr)
    sw      x1w, 8(sptr)
    sw      y1w, 12(sptr)
    sw      x2w, 16(sptr)
    sw      y2w, 20(sptr)
    sw      x3w, 24(sptr)
    sw      y3w, 28(sptr)
    sw      x4w, 32(sptr)
    sw      y4w, 36(sptr)
    sw      x5w, 40(sptr)
    sw      y5w, 44(sptr)
    // pop nine callee-saved registers
    lw      s1, 0(sp)
    lw      s2, 4(sp)
    lw      s3, 8(sp)
    lw      s4, 12(sp)
    lw      s5, 16(sp)
    lw      s6, 20(sp)
    lw      s7, 24(sp)
    lw      s8, 28(sp)
    lw      s9, 32(sp)
    // deallocate space on stack
    addi    sp, sp, 36
.endm


// addition of step-counter
.macro ADD_STEP_CNT_384
    lw      txy, 0(cptr) 
    add     cptr, cptr, 4 // cptr = cptr + 4 
    xor     y1w, y1w, cnt // xor y1w and cnt and stores it in y1w 
    xor     y0w, y0w, txy
.endm


// operation B = B + (A >>> dist)
.macro ADDROR bw:req, aw:req, dist:req
    srli    trr, \aw, \dist   // shift right by the amount in \dist  
    add     \bw, \bw, trr
    slli    trr, \aw, 32-(\dist)// shift left by the amount in \dist  
    add     \bw, \bw, trr
.endm


// operation B = B ^ (A >>> dist)
.macro XORROR bw:req, aw:req, dist:req
    srli    trr, \aw, \dist
    xor     \bw, \bw, trr
    slli    trr, \aw, 32-(\dist)
    xor     \bw, \bw, trr
.endm


// complete ARX-box (Alzette)
.macro ARX_BOX xi:req, yi:req, ci:req
    ADDROR  \xi, \yi, 31    // X = X + (Y >>> 31)
    XORROR  \yi, \xi, 24    // Y = Y ^ (X >>> 24)
    xor     \xi, \xi, \ci   // X = X ^ RCON
    ADDROR  \xi, \yi, 17    // X = X + (Y >>> 17)
    XORROR  \yi, \xi, 17    // Y = Y ^ (X >>> 17)
    xor     \xi, \xi, \ci   // X = X ^ RCON
    add     \xi, \xi, \yi   // X = X + Y
    XORROR  \yi, \xi, 31    // Y = Y ^ (X >>> 31)
    xor     \xi, \xi, \ci   // X = X ^ RCON
    ADDROR  \xi, \yi, 24    // X = X + (Y >>> 24)
    XORROR  \yi, \xi, 16    // Y = Y ^ (X >>> 16)
    xor     \xi, \xi, \ci   // X = X ^ RCON
.endm


// complete non-linear layer
.macro ARXBOX_LAYER_384
    ARX_BOX x0w, y0w, c0w
    ARX_BOX x1w, y1w, c1w
    ARX_BOX x2w, y2w, c2w
    ARX_BOX x3w, y3w, c3w
    ARX_BOX x4w, y4w, c4w
    ARX_BOX x5w, y5w, c5w
.endm


// computation of tx, ty
.macro TMPXY l0:req, l1:req, l2:req, r0:req, r1:req, r2:req
    xor     txy, \l0, \l1
    xor     txy, txy, \l2
    slli    trr, txy, 16
    xor     txy, txy, trr
    srli    trr, txy, 16
    slli    txy, txy, 16
    xor     txy, txy, trr
    xor     \r0, \r0, txy
    xor     \r1, \r1, txy
    xor     txy, \r2, txy
.endm


// branch permutation
.macro BPERM l0:req, l1:req, l2:req, r0:req, r1:req, r2:req
    mv      \r2, \l2
    xor     \l2, \r0, \l0
    mv      \r0, \l0
    xor     \l0, \r1, \l1
    mv      \r1, \l1
    xor     \l1, txy, \r2
.endm


// complete linear layer
.macro LINEAR_LAYER_384
    TMPXY   x0w, x1w, x2w, y3w, y4w, y5w
    BPERM   y0w, y1w, y2w, y3w, y4w, y5w
    TMPXY   y3w, y4w, y5w, x3w, x4w, x5w
    BPERM   x0w, x1w, x2w, x3w, x4w, x5w
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////// SPARKLE384 PERMUTATION (BRANCH-UNROLLED) ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle384_rv32(uint32_t *state, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32_t-array containing the 12 state words
// steps: number of steps
//
// Return value:
// -------------
// None

.type sparkle384_rv32, %function
.func sparkle384_rv32
sparkle384_rv32:
    PROLOGUE_384                // push callee-saved registers and load state
    mv cnt, zero                // initialize step-counter
.Lloop_384:                     // start of loop
    ADD_STEP_CNT_384            // macro to add step-counter to state
    ARXBOX_LAYER_384            // macro for the ARXBOX layer
    LINEAR_LAYER_384            // macro for the linear layer
    addi cnt, cnt, 1            // increment step-counter
    bne cnt, step, .Lloop_384   // test whether step-counter equals 'steps'
    EPILOGUE_384                // store state and pop callee-saved registers
    ret                         // return to caller
.endfunc


.size sparkle384_rv32, .-sparkle384_rv32


///////////////////////////////////////////////////////////////////////////////
/////////////////////////// SPARKLE ROUND CONSTANTS ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

// This implementation places the round constants in the .data segment, which
// means they are loaded from RAM during the computation of the ARX-boxes. It
// would also be possible to place them in the .rodata segment (by replacing
// the ".section .data" directive below by ".section .rodata") so that they are
// loaded from flash, which reduces the RAM consumption by 44 bytes, but may
// increase the execution time on devices with a high number of flash wait
// states.

.section .data
.balign 4


.type RCON, %object
.size RCON, 44
RCON:
.word 0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738
.word 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D
.word 0xB7E15162, 0xBF715880, 0x38B4DA56


.end
