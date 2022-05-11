.global tiny_rv32 

#define sptr a0
#define kptr a1
#define nround a2
#define st0 a3
#define st1 a4
#define st2 a5
#define st3 a6
#define kk0 t0 
#define kk1 t1 
#define kk2 t2 
#define kk3 t3 
#define temp1 t4 
#define temp2 t5 
#define tt1 s1 
#define tt2 s2
#define tt3 s3
#define tt4 s4
#define tt5 s5 
#define cnt s6


.macro PROLOGUE_TINY
    addi sp, sp, -20
    sw s1, 0(sp) 
    sw s2, 4(sp) 
    sw s3, 8(sp) 
    sw s4, 12(sp)
    sw s5, 16(sp)
    sw s6, 20(sp)

    lw st0, 0(sptr)
    lw st1, 4(sptr)
    lw st2, 8(sptr)
    lw st3, 12(sptr)
    lw kk0, 16(kptr)
    lw kk1, 20(kptr)
    lw kk2, 24(kptr)
    lw kk3, 28(kptr)
    
.endm

.macro EPILOGUE_TINY
    sw st0, 0(sptr)
    sw st1, 4(sptr)
    sw st2, 8(sptr)
    sw st3, 12(sptr)
    sw kk0, 16(kptr)
    sw kk1, 20(kptr)
    sw kk2, 24(kptr)
    sw kk3, 28(kptr)

    lw s1, 0(sp) 
    lw s2, 4(sp) 
    lw s3, 8(sp) 
    lw s4, 12(sp)
    lw s5, 16(sp)
    lw s6, 20(sp)
    addi sp, sp, 20
.endm


.macro LOGIC 
    srli temp1, st1, 15
    slli temp2, st2, 17
    or tt1, temp1, temp2 

    srli temp1, st2, 6
    slli temp2, st3, 26 
    or tt2, temp1, temp2 

    srli temp1, st2, 21
    slli temp2, st3, 11
    or tt3, temp1, temp2 

    srli temp1, st2, 27
    slli temp2, st3, 5 
    or tt4, temp1, temp2 

    and tt5, tt2, tt3 
    not tt5, tt5 
    xor tt1, tt1, tt5 
    xor tt1, tt1, tt4 
    xor tt1, tt1, kk0 
    xor st0, st0, tt1 

    // part 2

    srli temp1, st2, 15
    slli temp2, st3, 17
    or tt1, temp1, temp2 

    srli temp1, st3, 6
    slli temp2, st0, 26 
    or tt2, temp1, temp2 

    srli temp1, st3, 21
    slli temp2, st0, 11
    or tt3, temp1, temp2 

    srli temp1, st3, 27
    slli temp2, st0, 5 
    or tt4, temp1, temp2 

    and tt5, tt2, tt3 
    not tt5, tt5 
    xor tt1, tt1, tt5 
    xor tt1, tt1, tt4 
    xor tt1, tt1, kk1 
    xor st1, st1, tt1 

    // part 3 

    srli temp1, st3, 15
    slli temp2, st0, 17
    or tt1, temp1, temp2 

    srli temp1, st0, 6
    slli temp2, st1, 26 
    or tt2, temp1, temp2 

    srli temp1, st0, 21
    slli temp2, st1, 11
    or tt3, temp1, temp2 

    srli temp1, st0, 27
    slli temp2, st1, 5 
    or tt4, temp1, temp2 

    and tt5, tt2, tt3 
    not tt5, tt5 
    xor tt1, tt1, tt5 
    xor tt1, tt1, tt4 
    xor tt1, tt1, kk2 
    xor st2, st2, tt1 

    // part 4
    srli temp1, st0, 15
    slli temp2, st1, 17
    or tt1, temp1, temp2 

    srli temp1, st1, 6
    slli temp2, st2, 26 
    or tt2, temp1, temp2 

    srli temp1, st1, 21
    slli temp2, st2, 11
    or tt3, temp1, temp2 

    srli temp1, st1, 27
    slli temp2, st2, 5 
    or tt4, temp1, temp2 

    and tt5, tt2, tt3 
    not tt5, tt5 
    xor tt1, tt1, tt5 
    xor tt1, tt1, tt4 
    xor tt1, tt1, kk3 
    xor st3, st3, tt1 
.endm

.type tiny_rv32, %function
.func tiny_rv32
tiny_rv32:
    PROLOGUE_TINY               
    mv cnt, zero                
.Lloop:                    
    LOGIC
    addi cnt, cnt, 128            
    bne cnt, nround, .Lloop   
    EPILOGUE_TINY              
    ret                        
.endfunc