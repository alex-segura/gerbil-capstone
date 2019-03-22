;; -*- Gerbil -*-

(import :std/os/error
        :std/foreign)

(export #t)

(export disassemble
        with-capstone-context)

(begin-ffi (csh
            cs_arch
            cs_mode
            cs_malloc_t
            cs_calloc_t
            cs_realloc_t
            cs_free_t
            cs_vsnprintf_t
            cs_opt_mem
            cs_opt_value
            cs_op_type
            cs_group_type
            cs_skipdata_cb_t
            cs_opt_skipdata
            cs_detail
            cs_insn
            cs_err
            cs_version
            cs_open
            cs_option
            cs_errno
            cs_strerror
            cs_disasm
            cs_disasm_ex
            cs_free
            cs_malloc
            cs_disasm_iter
            cs_reg_name
            cs_insn_name
            cs_group_name
            cs_insn_group
            cs_reg_write
            cs_op_count
            cs_op_index)

  (define-macro (defenum name-and-c-name . enum-values)
    (let ((name (car name-and-c-name))
          (c-name (cadr name-and-c-name)))
      `(begin
         (c-define-type ,name ,c-name)
         ,@(map (lambda (enum) `(define-const ,enum)) enum-values))))

  (c-declare "#include <capstone.h>")

  (c-define-type csh "csh")
  (c-define-type csh* (pointer csh))

  (defenum (cs_arch "cs_arch")
    CS_ARCH_ARM
    CS_ARCH_ARM64
    CS_ARCH_MIPS
    CS_ARCH_X86
    CS_ARCH_PPC
    CS_ARCH_SPARC
    CS_ARCH_SYSZ
    CS_ARCH_XCORE
    CS_ARCH_MAX
    CS_ARCH_ALL)

  (defenum (cs_mode "cs_mode")
    CS_MODE_LITTLE_ENDIAN
    CS_MODE_ARM
    CS_MODE_16
    CS_MODE_32
    CS_MODE_64
    CS_MODE_THUMB
    CS_MODE_MCLASS
    CS_MODE_V8
    CS_MODE_MICRO
    CS_MODE_MIPS3
    CS_MODE_MIPS32R6
    CS_MODE_MIPSGP64
    CS_MODE_V9
    CS_MODE_BIG_ENDIAN
    CS_MODE_MIPS32
    CS_MODE_MIPS64)

  (c-define-type cs_opt_mem "cs_opt_mem")

  (defenum (cs_opt_type "cs_opt_type")
    CS_OPT_SYNTAX
    CS_OPT_DETAIL
    CS_OPT_MODE
    CS_OPT_MEM
    CS_OPT_SKIPDATA
    CS_OPT_SKIPDATA_SETUP)

  (defenum (cs_opt_value "cs_opt_value")
    CS_OPT_OFF
    CS_OPT_ON
    CS_OPT_SYNTAX_DEFAULT
    CS_OPT_SYNTAX_INTEL
    CS_OPT_SYNTAX_ATT
    CS_OPT_SYNTAX_NOREGNAME)

  (defenum (cs_op_type "cs_opt_type")
    CS_OP_INVALID
    CS_OP_REG
    CS_OP_IMM
    CS_OP_MEM
    CS_OP_FP)

  (defenum (cs_group_type "cs_group_type")
    CS_GRP_INVALID
    CS_GRP_JUMP
    CS_GRP_CALL
    CS_GRP_RET
    CS_GRP_INT
    CS_GRP_IRET)

  (c-define-type cs_opt_skipdata "cs_opt_skipdata")

  (c-define-type cs_detail "cs_detail")

  (c-define-type cs_insn "cs_insn")
  (c-define-type cs_insn* (pointer cs_insn))

  (defenum (cs_err "cs_err")
    CS_ERR_OK
    CS_ERR_MEM
    CS_ERR_ARCH
    CS_ERR_HANDLE
    CS_ERR_CSH
    CS_ERR_MODE
    CS_ERR_OPTION
    CS_ERR_DETAIL
    CS_ERR_MEMSETUP
    CS_ERR_VERSION
    CS_ERR_DIET
    CS_ERR_SKIPDATA
    CS_ERR_X86_ATT
    CS_ERR_X86_INTEL)

  (define-c-lambda cs_support (int) bool
    "cs_support (___arg1);")

  (define-c-lambda cs_open (cs_arch cs_mode csh*) cs_err
    "cs_open (___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_close (csh*) cs_err
    "cs_close (___arg1);")

  (define-c-lambda cs_option (csh cs_opt_type size_t) cs_err
    "cs_option (___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_errno (csh) cs_err
    "cs_errno (___arg1);")

  (define-c-lambda cs_strerror (cs_err) char-string
    "cs_strerror (___arg1);")

  (define-c-lambda cs_disasm (csh
                              (pointer unsigned-int8)
                              size_t
                              unsigned-int64
                              size_t
                              (pointer cs_insn*))
    size_t
    "cs_disasm (___arg1, ___arg2, ___arg3, ___arg4, ___arg5, ___arg6);")


  (define-c-lambda cs_free (cs_insn* size_t) void
    "cs_free(___arg1, ___arg2);")

  (define-c-lambda cs_malloc (csh) cs_insn*
    "cs_malloc(___arg1);")

  (define-c-lambda cs_disasm_iter
    (csh
     (pointer (pointer unsigned-int8))
     (pointer size_t)
     (pointer unsigned-int64)
     cs_insn*)
    bool
    "cs_disasm_iter(___arg1, ___arg2, ___arg3, ___arg4, ___arg5);")

  (define-c-lambda cs_reg_name (csh unsigned-int) char-string
    "cs_reg_name(___arg1, ___arg2);")


  (define-c-lambda cs_insn_name (csh unsigned-int) char-string
    "cs_insn_name(___arg1, ___arg2);")

  (define-c-lambda cs_group_name (csh unsigned-int) char-string
    "cs_group_name(___arg1, ___arg2);")

  (define-c-lambda cs_insn_group (csh cs_insn* unsigned-int) bool
    "cs_insn_group(___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_reg_read (csh cs_insn* unsigned-int) bool
    "cs_reg_read(___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_reg_write (csh cs_insn* unsigned-int) bool
    "cs_reg_write(___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_op_count (csh cs_insn* unsigned-int) int
    "cs_op_count(___arg1, ___arg2, ___arg3);")

  (define-c-lambda cs_op_index (csh cs_insn* unsigned-int unsigned-int) int
    "cs_op_index(___arg1, ___arg2, ___arg3, ___arg4);")


  ;; ARM

  (defenum (arm_cpsflag_type "arm_cpsflag_type"))
  (defenum (arm_vectordata_type "arm_vectordata_type"))

  (c-define-type arm_op_mem "arm_op_mem")
  (c-define-type cs_arm_op "cs_arm_op")
  (c-define-type cs_arm "cs_arm")

  (defenum (arm_reg "arm_reg")
    ARM_REG_INVALID = 0
    ARM_REG_APSR
    ARM_REG_APSR_NZCV
    ARM_REG_CPSR
    ARM_REG_FPEXC
    ARM_REG_FPINST
    ARM_REG_FPSCR
    ARM_REG_FPSCR_NZCV
    ARM_REG_FPSID
    ARM_REG_ITSTATE
    ARM_REG_LR
    ARM_REG_PC
    ARM_REG_SP
    ARM_REG_SPSR
    ARM_REG_D0
    ARM_REG_D1
    ARM_REG_D2
    ARM_REG_D3
    ARM_REG_D4
    ARM_REG_D5
    ARM_REG_D6
    ARM_REG_D7
    ARM_REG_D8
    ARM_REG_D9
    ARM_REG_D10
    ARM_REG_D11
    ARM_REG_D12
    ARM_REG_D13
    ARM_REG_D14
    ARM_REG_D15
    ARM_REG_D16
    ARM_REG_D17
    ARM_REG_D18
    ARM_REG_D19
    ARM_REG_D20
    ARM_REG_D21
    ARM_REG_D22
    ARM_REG_D23
    ARM_REG_D24
    ARM_REG_D25
    ARM_REG_D26
    ARM_REG_D27
    ARM_REG_D28
    ARM_REG_D29
    ARM_REG_D30
    ARM_REG_D31
    ARM_REG_FPINST2
    ARM_REG_MVFR0
    ARM_REG_MVFR1
    ARM_REG_MVFR2
    ARM_REG_Q0
    ARM_REG_Q1
    ARM_REG_Q2
    ARM_REG_Q3
    ARM_REG_Q4
    ARM_REG_Q5
    ARM_REG_Q6
    ARM_REG_Q7
    ARM_REG_Q8
    ARM_REG_Q9
    ARM_REG_Q10
    ARM_REG_Q11
    ARM_REG_Q12
    ARM_REG_Q13
    ARM_REG_Q14
    ARM_REG_Q15
    ARM_REG_R0
    ARM_REG_R1
    ARM_REG_R2
    ARM_REG_R3
    ARM_REG_R4
    ARM_REG_R5
    ARM_REG_R6
    ARM_REG_R7
    ARM_REG_R8
    ARM_REG_R9
    ARM_REG_R10
    ARM_REG_R11
    ARM_REG_R12
    ARM_REG_S0
    ARM_REG_S1
    ARM_REG_S2
    ARM_REG_S3
    ARM_REG_S4
    ARM_REG_S5
    ARM_REG_S6
    ARM_REG_S7
    ARM_REG_S8
    ARM_REG_S9
    ARM_REG_S10
    ARM_REG_S11
    ARM_REG_S12
    ARM_REG_S13
    ARM_REG_S14
    ARM_REG_S15
    ARM_REG_S16
    ARM_REG_S17
    ARM_REG_S18
    ARM_REG_S19
    ARM_REG_S20
    ARM_REG_S21
    ARM_REG_S22
    ARM_REG_S23
    ARM_REG_S24
    ARM_REG_S25
    ARM_REG_S26
    ARM_REG_S27
    ARM_REG_S28
    ARM_REG_S29
    ARM_REG_S30
    ARM_REG_S31
    ARM_REG_ENDING
    ARM_REG_R13
    ARM_REG_R14
    ARM_REG_R15
    ARM_REG_SB
    ARM_REG_SL
    ARM_REG_FP
    ARM_REG_IP)

  (defenum (arm_insn "arm_insn")
    ARM_INS_INVALID = 0
    ARM_INS_ADC
    ARM_INS_ADD
    ARM_INS_ADR
    ARM_INS_AESD
    ARM_INS_AESE
    ARM_INS_AESIMC
    ARM_INS_AESMC
    ARM_INS_AND
    ARM_INS_BFC
    ARM_INS_BFI
    ARM_INS_BIC
    ARM_INS_BKPT
    ARM_INS_BL
    ARM_INS_BLX
    ARM_INS_BX
    ARM_INS_BXJ
    ARM_INS_B
    ARM_INS_CDP
    ARM_INS_CDP2
    ARM_INS_CLREX
    ARM_INS_CLZ
    ARM_INS_CMN
    ARM_INS_CMP
    ARM_INS_CPS
    ARM_INS_CRC32B
    ARM_INS_CRC32CB
    ARM_INS_CRC32CH
    ARM_INS_CRC32CW
    ARM_INS_CRC32H
    ARM_INS_CRC32W
    ARM_INS_DBG
    ARM_INS_DMB
    ARM_INS_DSB
    ARM_INS_EOR
    ARM_INS_VMOV
    ARM_INS_FLDMDBX
    ARM_INS_FLDMIAX
    ARM_INS_VMRS
    ARM_INS_FSTMDBX
    ARM_INS_FSTMIAX
    ARM_INS_HINT
    ARM_INS_HLT
    ARM_INS_ISB
    ARM_INS_LDA
    ARM_INS_LDAB
    ARM_INS_LDAEX
    ARM_INS_LDAEXB
    ARM_INS_LDAEXD
    ARM_INS_LDAEXH
    ARM_INS_LDAH
    ARM_INS_LDC2L
    ARM_INS_LDC2
    ARM_INS_LDCL
    ARM_INS_LDC
    ARM_INS_LDMDA
    ARM_INS_LDMDB
    ARM_INS_LDM
    ARM_INS_LDMIB
    ARM_INS_LDRBT
    ARM_INS_LDRB
    ARM_INS_LDRD
    ARM_INS_LDREX
    ARM_INS_LDREXB
    ARM_INS_LDREXD
    ARM_INS_LDREXH
    ARM_INS_LDRH
    ARM_INS_LDRHT
    ARM_INS_LDRSB
    ARM_INS_LDRSBT
    ARM_INS_LDRSH
    ARM_INS_LDRSHT
    ARM_INS_LDRT
    ARM_INS_LDR
    ARM_INS_MCR
    ARM_INS_MCR2
    ARM_INS_MCRR
    ARM_INS_MCRR2
    ARM_INS_MLA
    ARM_INS_MLS
    ARM_INS_MOV
    ARM_INS_MOVT
    ARM_INS_MOVW
    ARM_INS_MRC
    ARM_INS_MRC2
    ARM_INS_MRRC
    ARM_INS_MRRC2
    ARM_INS_MRS
    ARM_INS_MSR
    ARM_INS_MUL
    ARM_INS_MVN
    ARM_INS_ORR
    ARM_INS_PKHBT
    ARM_INS_PKHTB
    ARM_INS_PLDW
    ARM_INS_PLD
    ARM_INS_PLI
    ARM_INS_QADD
    ARM_INS_QADD16
    ARM_INS_QADD8
    ARM_INS_QASX
    ARM_INS_QDADD
    ARM_INS_QDSUB
    ARM_INS_QSAX
    ARM_INS_QSUB
    ARM_INS_QSUB16
    ARM_INS_QSUB8
    ARM_INS_RBIT
    ARM_INS_REV
    ARM_INS_REV16
    ARM_INS_REVSH
    ARM_INS_RFEDA
    ARM_INS_RFEDB
    ARM_INS_RFEIA
    ARM_INS_RFEIB
    ARM_INS_RSB
    ARM_INS_RSC
    ARM_INS_SADD16
    ARM_INS_SADD8
    ARM_INS_SASX
    ARM_INS_SBC
    ARM_INS_SBFX
    ARM_INS_SDIV
    ARM_INS_SEL
    ARM_INS_SETEND
    ARM_INS_SHA1C
    ARM_INS_SHA1H
    ARM_INS_SHA1M
    ARM_INS_SHA1P
    ARM_INS_SHA1SU0
    ARM_INS_SHA1SU1
    ARM_INS_SHA256H
    ARM_INS_SHA256H2
    ARM_INS_SHA256SU0
    ARM_INS_SHA256SU1
    ARM_INS_SHADD16
    ARM_INS_SHADD8
    ARM_INS_SHASX
    ARM_INS_SHSAX
    ARM_INS_SHSUB16
    ARM_INS_SHSUB8
    ARM_INS_SMC
    ARM_INS_SMLABB
    ARM_INS_SMLABT
    ARM_INS_SMLAD
    ARM_INS_SMLADX
    ARM_INS_SMLAL
    ARM_INS_SMLALBB
    ARM_INS_SMLALBT
    ARM_INS_SMLALD
    ARM_INS_SMLALDX
    ARM_INS_SMLALTB
    ARM_INS_SMLALTT
    ARM_INS_SMLATB
    ARM_INS_SMLATT
    ARM_INS_SMLAWB
    ARM_INS_SMLAWT
    ARM_INS_SMLSD
    ARM_INS_SMLSDX
    ARM_INS_SMLSLD
    ARM_INS_SMLSLDX
    ARM_INS_SMMLA
    ARM_INS_SMMLAR
    ARM_INS_SMMLS
    ARM_INS_SMMLSR
    ARM_INS_SMMUL
    ARM_INS_SMMULR
    ARM_INS_SMUAD
    ARM_INS_SMUADX
    ARM_INS_SMULBB
    ARM_INS_SMULBT
    ARM_INS_SMULL
    ARM_INS_SMULTB
    ARM_INS_SMULTT
    ARM_INS_SMULWB
    ARM_INS_SMULWT
    ARM_INS_SMUSD
    ARM_INS_SMUSDX
    ARM_INS_SRSDA
    ARM_INS_SRSDB
    ARM_INS_SRSIA
    ARM_INS_SRSIB
    ARM_INS_SSAT
    ARM_INS_SSAT16
    ARM_INS_SSAX
    ARM_INS_SSUB16
    ARM_INS_SSUB8
    ARM_INS_STC2L
    ARM_INS_STC2
    ARM_INS_STCL
    ARM_INS_STC
    ARM_INS_STL
    ARM_INS_STLB
    ARM_INS_STLEX
    ARM_INS_STLEXB
    ARM_INS_STLEXD
    ARM_INS_STLEXH
    ARM_INS_STLH
    ARM_INS_STMDA
    ARM_INS_STMDB
    ARM_INS_STM
    ARM_INS_STMIB
    ARM_INS_STRBT
    ARM_INS_STRB
    ARM_INS_STRD
    ARM_INS_STREX
    ARM_INS_STREXB
    ARM_INS_STREXD
    ARM_INS_STREXH
    ARM_INS_STRH
    ARM_INS_STRHT
    ARM_INS_STRT
    ARM_INS_STR
    ARM_INS_SUB
    ARM_INS_SVC
    ARM_INS_SWP
    ARM_INS_SWPB
    ARM_INS_SXTAB
    ARM_INS_SXTAB16
    ARM_INS_SXTAH
    ARM_INS_SXTB
    ARM_INS_SXTB16
    ARM_INS_SXTH
    ARM_INS_TEQ
    ARM_INS_TRAP
    ARM_INS_TST
    ARM_INS_UADD16
    ARM_INS_UADD8
    ARM_INS_UASX
    ARM_INS_UBFX
    ARM_INS_UDF
    ARM_INS_UDIV
    ARM_INS_UHADD16
    ARM_INS_UHADD8
    ARM_INS_UHASX
    ARM_INS_UHSAX
    ARM_INS_UHSUB16
    ARM_INS_UHSUB8
    ARM_INS_UMAAL
    ARM_INS_UMLAL
    ARM_INS_UMULL
    ARM_INS_UQADD16
    ARM_INS_UQADD8
    ARM_INS_UQASX
    ARM_INS_UQSAX
    ARM_INS_UQSUB16
    ARM_INS_UQSUB8
    ARM_INS_USAD8
    ARM_INS_USADA8
    ARM_INS_USAT
    ARM_INS_USAT16
    ARM_INS_USAX
    ARM_INS_USUB16
    ARM_INS_USUB8
    ARM_INS_UXTAB
    ARM_INS_UXTAB16
    ARM_INS_UXTAH
    ARM_INS_UXTB
    ARM_INS_UXTB16
    ARM_INS_UXTH
    ARM_INS_VABAL
    ARM_INS_VABA
    ARM_INS_VABDL
    ARM_INS_VABD
    ARM_INS_VABS
    ARM_INS_VACGE
    ARM_INS_VACGT
    ARM_INS_VADD
    ARM_INS_VADDHN
    ARM_INS_VADDL
    ARM_INS_VADDW
    ARM_INS_VAND
    ARM_INS_VBIC
    ARM_INS_VBIF
    ARM_INS_VBIT
    ARM_INS_VBSL
    ARM_INS_VCEQ
    ARM_INS_VCGE
    ARM_INS_VCGT
    ARM_INS_VCLE
    ARM_INS_VCLS
    ARM_INS_VCLT
    ARM_INS_VCLZ
    ARM_INS_VCMP
    ARM_INS_VCMPE
    ARM_INS_VCNT
    ARM_INS_VCVTA
    ARM_INS_VCVTB
    ARM_INS_VCVT
    ARM_INS_VCVTM
    ARM_INS_VCVTN
    ARM_INS_VCVTP
    ARM_INS_VCVTT
    ARM_INS_VDIV
    ARM_INS_VDUP
    ARM_INS_VEOR
    ARM_INS_VEXT
    ARM_INS_VFMA
    ARM_INS_VFMS
    ARM_INS_VFNMA
    ARM_INS_VFNMS
    ARM_INS_VHADD
    ARM_INS_VHSUB
    ARM_INS_VLD1
    ARM_INS_VLD2
    ARM_INS_VLD3
    ARM_INS_VLD4
    ARM_INS_VLDMDB
    ARM_INS_VLDMIA
    ARM_INS_VLDR
    ARM_INS_VMAXNM
    ARM_INS_VMAX
    ARM_INS_VMINNM
    ARM_INS_VMIN
    ARM_INS_VMLA
    ARM_INS_VMLAL
    ARM_INS_VMLS
    ARM_INS_VMLSL
    ARM_INS_VMOVL
    ARM_INS_VMOVN
    ARM_INS_VMSR
    ARM_INS_VMUL
    ARM_INS_VMULL
    ARM_INS_VMVN
    ARM_INS_VNEG
    ARM_INS_VNMLA
    ARM_INS_VNMLS
    ARM_INS_VNMUL
    ARM_INS_VORN
    ARM_INS_VORR
    ARM_INS_VPADAL
    ARM_INS_VPADDL
    ARM_INS_VPADD
    ARM_INS_VPMAX
    ARM_INS_VPMIN
    ARM_INS_VQABS
    ARM_INS_VQADD
    ARM_INS_VQDMLAL
    ARM_INS_VQDMLSL
    ARM_INS_VQDMULH
    ARM_INS_VQDMULL
    ARM_INS_VQMOVUN
    ARM_INS_VQMOVN
    ARM_INS_VQNEG
    ARM_INS_VQRDMULH
    ARM_INS_VQRSHL
    ARM_INS_VQRSHRN
    ARM_INS_VQRSHRUN
    ARM_INS_VQSHL
    ARM_INS_VQSHLU
    ARM_INS_VQSHRN
    ARM_INS_VQSHRUN
    ARM_INS_VQSUB
    ARM_INS_VRADDHN
    ARM_INS_VRECPE
    ARM_INS_VRECPS
    ARM_INS_VREV16
    ARM_INS_VREV32
    ARM_INS_VREV64
    ARM_INS_VRHADD
    ARM_INS_VRINTA
    ARM_INS_VRINTM
    ARM_INS_VRINTN
    ARM_INS_VRINTP
    ARM_INS_VRINTR
    ARM_INS_VRINTX
    ARM_INS_VRINTZ
    ARM_INS_VRSHL
    ARM_INS_VRSHRN
    ARM_INS_VRSHR
    ARM_INS_VRSQRTE
    ARM_INS_VRSQRTS
    ARM_INS_VRSRA
    ARM_INS_VRSUBHN
    ARM_INS_VSELEQ
    ARM_INS_VSELGE
    ARM_INS_VSELGT
    ARM_INS_VSELVS
    ARM_INS_VSHLL
    ARM_INS_VSHL
    ARM_INS_VSHRN
    ARM_INS_VSHR
    ARM_INS_VSLI
    ARM_INS_VSQRT
    ARM_INS_VSRA
    ARM_INS_VSRI
    ARM_INS_VST1
    ARM_INS_VST2
    ARM_INS_VST3
    ARM_INS_VST4
    ARM_INS_VSTMDB
    ARM_INS_VSTMIA
    ARM_INS_VSTR
    ARM_INS_VSUB
    ARM_INS_VSUBHN
    ARM_INS_VSUBL
    ARM_INS_VSUBW
    ARM_INS_VSWP
    ARM_INS_VTBL
    ARM_INS_VTBX
    ARM_INS_VCVTR
    ARM_INS_VTRN
    ARM_INS_VTST
    ARM_INS_VUZP
    ARM_INS_VZIP
    ARM_INS_ADDW
    ARM_INS_ASR
    ARM_INS_DCPS1
    ARM_INS_DCPS2
    ARM_INS_DCPS3
    ARM_INS_IT
    ARM_INS_LSL
    ARM_INS_LSR
    ARM_INS_ASRS
    ARM_INS_LSRS
    ARM_INS_ORN
    ARM_INS_ROR
    ARM_INS_RRX
    ARM_INS_SUBS
    ARM_INS_SUBW
    ARM_INS_TBB
    ARM_INS_TBH
    ARM_INS_CBNZ
    ARM_INS_CBZ
    ARM_INS_MOVS
    ARM_INS_POP
    ARM_INS_PUSH
    ARM_INS_NOP
    ARM_INS_YIELD
    ARM_INS_WFE
    ARM_INS_WFI
    ARM_INS_SEV
    ARM_INS_SEVL
    ARM_INS_VPUSH
    ARM_INS_VPOP
    ARM_INS_ENDING)

  (defenum (arm_insn_group "arm_insn_group")
    ARM_GRP_INVALID
    ARM_GRP_JUMP
    ARM_GRP_CRYPTO
    ARM_GRP_DATABARRIER
    ARM_GRP_DIVIDE
    ARM_GRP_FPARMV8
    ARM_GRP_MULTPRO
    ARM_GRP_NEON
    ARM_GRP_T2EXTRACTPACK
    ARM_GRP_THUMB2DSP
    ARM_GRP_TRUSTZONE
    ARM_GRP_V4T
    ARM_GRP_V5T
    ARM_GRP_V5TE
    ARM_GRP_V6
    ARM_GRP_V6T2
    ARM_GRP_V7
    ARM_GRP_V8
    ARM_GRP_VFP2
    ARM_GRP_VFP3
    ARM_GRP_VFP4
    ARM_GRP_ARM
    ARM_GRP_MCLASS
    ARM_GRP_NOTMCLASS
    ARM_GRP_THUMB
    ARM_GRP_THUMB1ONLY
    ARM_GRP_THUMB2
    ARM_GRP_PREV8
    ARM_GRP_FPVMLX
    ARM_GRP_MULOPS
    ARM_GRP_CRC
    ARM_GRP_DPVFP
    ARM_GRP_V6M
    ARM_GRP_ENDING)

) ; begin-ffi
