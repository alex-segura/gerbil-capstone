;; -*- Gerbil -*-

(import :std/error
        :std/foreign
        :std/iter)

(export cs-open
        cs-close
        with-disassembler
        disassemble

        set-option!
        register-name
        instruction-name
        group-name

        instruction-in-group?
        instruction-reads-register?
        instruction-writes-register?
        instruction-operand-count
        instruction-operand-index

        instruction-address
        instruction-mnemonic
        instruction-operand-string
        instruction-detail
        instruction-detail-reg-read
        instruction-detail-reg-written
        instruction-detail-group

        instruction-detail-x86
        instruction-detail-arm64
        instruction-detail-arm
        instruction-detail-m68k
        instruction-detail-mipsen
        instruction-detail-ppc
        instruction-detail-sparc
        instruction-detail-sysz
        instruction-detail-xcore
        instruction-detail-tms320c64x
        instruction-detail-m680x
        instruction-detail-evm

        CS_ARCH_ARM
        CS_ARCH_ARM64
        CS_ARCH_MIPS
        CS_ARCH_X86
        CS_ARCH_PPC
        CS_ARCH_SPARC
        CS_ARCH_SYSZ
        CS_ARCH_XCORE
        CS_ARCH_MAX
        CS_ARCH_ALL

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
        CS_MODE_MIPS2
        CS_MODE_V9
        CS_MODE_QPX
        CS_MODE_M68K_000
        CS_MODE_M68K_010
        CS_MODE_M68K_020
        CS_MODE_M68K_030
        CS_MODE_M68K_040
        CS_MODE_M68K_060
        CS_MODE_BIG_ENDIAN
        CS_MODE_MIPS32
        CS_MODE_MIPS64
        CS_MODE_M680X_6301
        CS_MODE_M680X_6309
        CS_MODE_M680X_6800
        CS_MODE_M680X_6801
        CS_MODE_M680X_6805
        CS_MODE_M680X_6808
        CS_MODE_M680X_6809
        CS_MODE_M680X_6811
        CS_MODE_M680X_CPU12
        CS_MODE_M680X_HCS08

        CS_OP_INVALID
        CS_OP_REG
        CS_OP_IMM
        CS_OP_MEM
        CS_OP_FP)

(defstruct (capstone-error <error>) ())

(def (raise-capstone-error where code)
  (raise (make-capstone-error (cs_strerror code) [code] where)))

(def cs-handle (make-parameter #f))

(def (get-cs-handle) (get_csh (cs-handle)))

(def (cs-open arch: arch mode: mode)
  (let (csh* (make_csh))
    (let (err (cs_open arch mode csh*))
      (unless (= err CS_ERR_OK)
        (raise-capstone-error 'cs-open err))
      csh*)))

(def (cs-close csh)
  (let (err (cs_close csh))
    (unless (= err CS_ERR_OK)
      (raise-capstone-error 'cs-close err))))

(def (call-with-csh csh f)
  (parameterize ((cs-handle csh))
    (f)))

(defsyntax (with-disassembler stx)
  (syntax-case stx ()
    ((_ (arch: arch mode: mode) body ...)
     #'(call-with-csh
        (cs-open arch: arch mode: mode)
        (lambda ()
          (unwind-protect
            (begin body ...)
            (cs-close (cs-handle))))))
    ((_ expr body ...)
     #'(call-with-csh expr (lambda () body ...)))))

(def (disassemble bytes address: address count: count)
  (def (disassemble-iter csh bytes address count)
    (let (state (make_disasm_state csh bytes address))
      (lambda ()
        (let lp ((i 0))
          (when (< i count)
            (when (cs_disasm_step csh state)
              (yield (disasm_state_insn state))
              (lp (+ i 1))))))))
  (disassemble-iter (get-cs-handle) bytes address count))

(def* set-option!
  ((opt-type value) (set-option! (get-cs-handle) opt-type value))
  ((csh opt-type value)
   (let (err (cs_option csh opt-type value))
     (unless (= err CS_ERR_OK)
       (raise-capstone-error 'set-option! err)))))

(def* register-name
  ((id) (register-name (get-cs-handle) id))
  ((csh id) (cs_reg_name csh id)))

(def* instruction-name
  ((id) (instruction-name (get-cs-handle) id))
  ((csh id) (cs_insn_name csh id)))

(def* group-name
  ((id) (group-name (get-cs-handle) id))
  ((csh id) (cs_group_name csh id)))

(def* instruction-in-group?
  ((instruction group-id)
   (instruction-in-group? (get-cs-handle) instruction group-id))
  ((csh instruction group-id)
   (cs_insn_group csh instruction group-id)))

(def* instruction-reads-register?
  ((instruction reg-id)
   (instruction-reads-register? (get-cs-handle) instruction reg-id))
  ((csh instruction reg-id)
   (cs_reg_read csh instruction reg-id)))

(def* instruction-writes-register?
  ((instruction reg-id)
   (instruction-writes-register? (get-cs-handle) instruction reg-id))
  ((csh instruction reg-id)
   (cs_reg_write csh instruction reg-id)))

(def* instruction-operand-count
  ((instruction optype)
   (instruction-operand-count (get-cs-handle) instruction optype))
  ((csh instruction optype)
   (cs_op_count csh instruction optype)))

(def* instruction-operand-index
  ((instruction optype position)
   (instruction-operand-index (get-cs-handle) instruction optype position))
  ((csh instruction optype position)
   (cs_op_index csh instruction optype position)))

(def instruction-id cs_insn_id)
(def instruction-address cs_insn_address)
(def instruction-size cs_insn_size)
(def instruction-bytes cs_insn_bytes)
(def instruction-mnemonic cs_insn_mnemonic)
(def instruction-operand-string cs_insn_opstr)
(def instruction-detail cs_insn_detail)

(def (instruction-detail-reg-read detail ix)
  (let (count (cs_detail_regs_read_count detail))
    (when (##fx< ix count)
      (cs_detail_regs_read detail ix))))

(def (instruction-detail-reg-written detail ix)
  (let (count (cs_detail_regs_write_count detail))
    (when (##fx< ix count)
      (cs_detail_regs_write detail ix))))

(def (instruction-detail-group detail ix)
  (let (count (cs_detail_groups_count detail))
    (when (##fx< ix count)
      (cs_detail_groups detail ix))))

(def instruction-detail-x86 cs_detail_x86)
(def instruction-detail-arm64 cs_detail_arm64)
(def instruction-detail-arm cs_detail_arm)
(def instruction-detail-m68k cs_detail_m68k)
(def instruction-detail-mipsen cs_detail_mipsen)
(def instruction-detail-ppc cs_detail_ppc)
(def instruction-detail-sparc cs_detail_sparc)
(def instruction-detail-sysz cs_detail_sysz)
(def instruction-detail-xcore cs_detail_xcore)
(def instruction-detail-tms320c64x cs_detail_tms320c64x)
(def instruction-detail-m680x cs_detail_m680x)
(def instruction-detail-evm cs_detail_evm)

(begin-ffi (CS_ARCH_ARM
            CS_ARCH_ARM64
            CS_ARCH_MIPS
            CS_ARCH_X86
            CS_ARCH_PPC
            CS_ARCH_SPARC
            CS_ARCH_SYSZ
            CS_ARCH_XCORE
            CS_ARCH_MAX
            CS_ARCH_ALL

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
            CS_MODE_MIPS2
            CS_MODE_V9
            CS_MODE_QPX
            CS_MODE_M68K_000
            CS_MODE_M68K_010
            CS_MODE_M68K_020
            CS_MODE_M68K_030
            CS_MODE_M68K_040
            CS_MODE_M68K_060
            CS_MODE_BIG_ENDIAN
            CS_MODE_MIPS32
            CS_MODE_MIPS64
            CS_MODE_M680X_6301
            CS_MODE_M680X_6309
            CS_MODE_M680X_6800
            CS_MODE_M680X_6801
            CS_MODE_M680X_6805
            CS_MODE_M680X_6808
            CS_MODE_M680X_6809
            CS_MODE_M680X_6811
            CS_MODE_M680X_CPU12
            CS_MODE_M680X_HCS08

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
            CS_ERR_X86_INTEL

            CS_OP_INVALID
            CS_OP_REG
            CS_OP_IMM
            CS_OP_MEM
            CS_OP_FP

            CS_OPT_INVALID
            CS_OPT_SYNTAX
            CS_OPT_DETAIL
            CS_OPT_MODE
            CS_OPT_MEM
            CS_OPT_SKIPDATA
            CS_OPT_SKIPDATA_SETUP
            CS_OPT_MNEMONIC
            CS_OPT_UNSIGNED

            CS_OPT_OFF
            CS_OPT_ON
            CS_OPT_SYNTAX_DEFAULT
            CS_OPT_SYNTAX_INTEL
            CS_OPT_SYNTAX_ATT
            CS_OPT_SYNTAX_NOREGNAME
            CS_OPT_SYNTAX_MASM

            make_csh
            get_csh
            make_disasm_state
            disasm_state_insn
            disasm_state_address

            cs_insn_id
            cs_insn_address
            cs_insn_mnemonic
            cs_insn_opstr
            cs_insn_size
            cs_insn_bytes
            cs_insn_detail

            cs_detail_regs_read
            cs_detail_regs_read_count
            cs_detail_regs_write
            cs_detail_regs_write_count
            cs_detail_groups
            cs_detail_groups_count
            cs_detail_x86
            cs_detail_arm64
            cs_detail_arm
            cs_detail_m68k
            cs_detail_mipsen
            cs_detail_ppc
            cs_detail_sparc
            cs_detail_sysz
            cs_detail_xcore
            cs_detail_tms320c64x
            cs_detail_m680x
            cs_detail_evm

            cs_version
            cs_open
            cs_close
            cs_option
            cs_errno
            cs_strerror
            cs_disasm_step
            cs_free
            cs_malloc
            cs_reg_name
            cs_insn_name
            cs_group_name
            cs_insn_group
            cs_reg_read
            cs_reg_write
            cs_op_count
            cs_op_index
            cs_regs
            cs_regs_access)

  (define-macro (defenum name-and-c-name . enum-values)
    (let ((name (car name-and-c-name))
          (c-name (cadr name-and-c-name)))
      `(begin
         (c-define-type ,name int)
         ,@(map (lambda (enum) `(define-const ,enum)) enum-values))))

  (c-declare #<<END-C
#include <capstone/capstone.h>
#include <string.h>

static void ffi_free_insn(void *ptr);
static void free_disasm_state(void *ptr);

typedef struct disasm_state {
 uint8_t *code;
 size_t size;
 cs_insn *insn;
 uint64_t address;
} disasm_state;

END-C
)

  (c-define-type csh "size_t")
  (c-define-type csh* (pointer csh (csh*) "ffi_free"))
  (define-c-lambda make_csh () csh*
    "___return ((csh *) malloc (sizeof(csh)));")
  (define-c-lambda get_csh (csh*) csh
    "___return (*___arg1);")

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
    CS_MODE_MIPS2
    CS_MODE_V9
    CS_MODE_QPX
    CS_MODE_M68K_000
    CS_MODE_M68K_010
    CS_MODE_M68K_020
    CS_MODE_M68K_030
    CS_MODE_M68K_040
    CS_MODE_M68K_060
    CS_MODE_BIG_ENDIAN
    CS_MODE_MIPS32
    CS_MODE_MIPS64
    CS_MODE_M680X_6301
    CS_MODE_M680X_6309
    CS_MODE_M680X_6800
    CS_MODE_M680X_6801
    CS_MODE_M680X_6805
    CS_MODE_M680X_6808
    CS_MODE_M680X_6809
    CS_MODE_M680X_6811
    CS_MODE_M680X_CPU12
    CS_MODE_M680X_HCS08)

  (c-define-type cs_opt_mem "cs_opt_mem")

  (defenum (cs_opt_type "cs_opt_type")
    CS_OPT_INVALID
    CS_OPT_SYNTAX
    CS_OPT_DETAIL
    CS_OPT_MODE
    CS_OPT_MEM
    CS_OPT_SKIPDATA
    CS_OPT_SKIPDATA_SETUP
    CS_OPT_MNEMONIC
    CS_OPT_UNSIGNED)

  (defenum (cs_opt_value "cs_opt_value")
    CS_OPT_OFF
    CS_OPT_ON
    CS_OPT_SYNTAX_DEFAULT
    CS_OPT_SYNTAX_INTEL
    CS_OPT_SYNTAX_ATT
    CS_OPT_SYNTAX_NOREGNAME
    CS_OPT_SYNTAX_MASM)

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
  (c-define-type cs_detail* (pointer cs_detail))
  (c-define-type cs_insn "cs_insn")
  (c-define-type cs_insn* (pointer cs_insn))

  (c-define-type disasm_state (struct "disasm_state"))
  (c-define-type disasm_state*
                 (pointer disasm_state (disasm_state*) "free_disasm_state"))
  (define-c-lambda make_disasm_state (csh scheme-object unsigned-int64) disasm_state*
    "make_disasm_state")
  (define-c-lambda disasm_state_insn (disasm_state*) cs_insn*
    "___return (___arg1->insn);")
  (define-c-lambda disasm_state_address (disasm_state*) unsigned-int64
    "___return (___arg1->address);")

  (define-c-lambda cs_insn_id (cs_insn*) unsigned-int
    "___return (___arg1->id);")
  (define-c-lambda cs_insn_address (cs_insn*) unsigned-int64
    "___return (___arg1->address);")
  (define-c-lambda cs_insn_size (cs_insn*) unsigned-int16
    "___return (___arg1->size);")
  (define-c-lambda cs_insn_bytes (cs_insn* scheme-object) void
    "ffi_cs_insn_bytes")
  (define-c-lambda cs_insn_mnemonic (cs_insn*) char-string
    "___return (___arg1->mnemonic);")
  (define-c-lambda cs_insn_opstr (cs_insn*) char-string
    "___return (___arg1->op_str);")
  (define-c-lambda cs_insn_detail (cs_insn*) cs_detail*
    "___return (___arg1->detail);")
  (define-c-lambda cs_detail_regs_read (cs_detail* size_t) unsigned-int16
    "___return (___arg1->regs_read[___arg2]);")
  (define-c-lambda cs_detail_regs_read_count (cs_detail*) unsigned-int8
    "___return (___arg1->regs_read_count);")
  (define-c-lambda cs_detail_regs_write (cs_detail* size_t) unsigned-int16
    "___return (___arg1->regs_write[___arg2]);")
  (define-c-lambda cs_detail_regs_write_count (cs_detail*) unsigned-int8
    "___return (___arg1->regs_read_count);")
  (define-c-lambda cs_detail_groups (cs_detail* size_t) unsigned-int8
    "___return (___arg1->groups[___arg2]);")
  (define-c-lambda cs_detail_groups_count (cs_detail*) unsigned-int8
    "___return (___arg1->groups_count);")

  (c-define-type cs_x86 "cs_x86")
  (c-define-type cs_arm64 "cs_arm64")
  (c-define-type cs_arm "cs_arm")
  (c-define-type cs_m68k "cs_m68k")
  (c-define-type cs_mips "cs_mips")
  (c-define-type cs_ppc "cs_ppc")
  (c-define-type cs_sparc "cs_sparc")
  (c-define-type cs_sysz "cs_sysz")
  (c-define-type cs_xcore "cs_xcore")
  (c-define-type cs_tms320c64x "cs_tms320c64x")
  (c-define-type cs_m680x "cs_m680x")
  (c-define-type cs_evm "cs_evm")
  (c-define-type cs_x86* (pointer cs_x86))
  (c-define-type cs_arm64* (pointer cs_arm64))
  (c-define-type cs_arm* (pointer cs_arm))
  (c-define-type cs_m68k* (pointer cs_m68k))
  (c-define-type cs_mips* (pointer cs_mips))
  (c-define-type cs_ppc* (pointer cs_ppc))
  (c-define-type cs_sparc* (pointer cs_sparc))
  (c-define-type cs_sysz* (pointer cs_sysz))
  (c-define-type cs_xcore* (pointer cs_xcore))
  (c-define-type cs_tms320c64x* (pointer cs_tms320c64x))
  (c-define-type cs_m680x* (pointer cs_m680x))
  (c-define-type cs_evm* (pointer cs_evm))
  (define-c-lambda cs_detail_x86 (cs_detail*) cs_x86*
    "___return (&___arg1->x86);")
  (define-c-lambda cs_detail_arm64 (cs_detail*) cs_arm64*
    "___return (&___arg1->arm64);")
  (define-c-lambda cs_detail_arm (cs_detail*) cs_arm*
    "___return (&___arg1->arm);")
  (define-c-lambda cs_detail_m68k (cs_detail*) cs_m68k*
    "___return (&___arg1->m68k);")
  (define-c-lambda cs_detail_mipsen (cs_detail*) cs_mips*
    "___return (&___arg1->mipsen);")
  (define-c-lambda cs_detail_ppc (cs_detail*) cs_ppc*
    "___return (&___arg1->ppc);")
  (define-c-lambda cs_detail_sparc (cs_detail*) cs_sparc*
    "___return (&___arg1->sparc);")
  (define-c-lambda cs_detail_sysz (cs_detail*) cs_sysz*
    "___return (&___arg1->sysz);")
  (define-c-lambda cs_detail_xcore (cs_detail*) cs_xcore*
    "___return (&___arg1->xcore);")
  (define-c-lambda cs_detail_tms320c64x (cs_detail*) cs_tms320c64x*
    "___return (&___arg1->tms320c64x);")
  (define-c-lambda cs_detail_m680x (cs_detail*) cs_m680x*
    "___return (&___arg1->m680x);")
  (define-c-lambda cs_detail_evm (cs_detail*) cs_evm*
    "___return (&___arg1->evm);")

  (c-define-type cs_regs "cs_regs")

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
    "cs_support")
  (define-c-lambda cs_open (cs_arch cs_mode csh*) cs_err
    "cs_open")
  (define-c-lambda cs_close (csh*) cs_err
    "cs_close")
  (define-c-lambda cs_option (csh cs_opt_type size_t) cs_err
    "cs_option")
  (define-c-lambda cs_errno (csh) cs_err
    "cs_errno")
  (define-c-lambda cs_strerror (cs_err) char-string
    "cs_strerror")
  (define-c-lambda cs_disasm_step (csh disasm_state*) bool
    "cs_disasm_step")
  (define-c-lambda cs_free (cs_insn* size_t) void
    "cs_free")
  (define-c-lambda cs_malloc (csh) cs_insn*
    "cs_malloc")
  (define-c-lambda cs_reg_name (csh unsigned-int) char-string
    "cs_reg_name")
  (define-c-lambda cs_insn_name (csh unsigned-int) char-string
    "cs_insn_name")
  (define-c-lambda cs_group_name (csh unsigned-int) char-string
    "cs_group_name")
  (define-c-lambda cs_insn_group (csh cs_insn* unsigned-int) bool
    "cs_insn_group")
  (define-c-lambda cs_reg_read (csh cs_insn* unsigned-int) bool
    "cs_reg_read")
  (define-c-lambda cs_reg_write (csh cs_insn* unsigned-int) bool
    "cs_reg_write")
  (define-c-lambda cs_op_count (csh cs_insn* unsigned-int) int
    "cs_op_count")
  (define-c-lambda cs_op_index (csh cs_insn* unsigned-int unsigned-int) int
    "cs_op_index")
  (define-c-lambda cs_regs_access
    (csh cs_insn* cs_regs (pointer unsigned-int8) cs_regs (pointer unsigned-int8))
    cs_err
    "cs_regs_access")

  (c-declare #<<END-C

static void ffi_free_insn(void *insn)
{
 cs_free((cs_insn *)insn, 1);
}

static void ffi_cs_insn_bytes(cs_insn* insn, ___SCMOBJ bytes)
{
 uint8_t *data = U8_DATA(bytes);
 memcpy(data, insn->bytes, 16);
 return;
}

static disasm_state *make_disasm_state(csh handle, ___SCMOBJ bytes, uint64_t address)
{
 uint8_t *code = U8_DATA(bytes);
 size_t size = U8_LEN(bytes);
 cs_insn *insn = cs_malloc(handle);
 disasm_state *state = (disasm_state *) malloc(sizeof(disasm_state));
 if (!state)
  return NULL;
 state->code = code;
 state->size = size;
 state->insn = insn;
 state->address = address;
 return state;
}

static bool cs_disasm_step(csh handle, disasm_state *state)
{
 bool ok = cs_disasm_iter(handle, (const uint8_t **) &state->code,
  &state->size, &state->address, state->insn);
 return ok;
}

static void free_disasm_state(void *ptr)
{
 disasm_state *s = (disasm_state *)ptr;
 cs_free(s->insn, 1);
 free(s);
}

END-C
)

) ; begin-ffi
