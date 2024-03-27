// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * Install and remove a platform security2 override policy
 */
#include "shim.h"

#if defined(OVERRIDE_SECURITY_POLICY)

/*
 * See the UEFI Platform Initialization manual (Vol2: DXE) for this
 */
struct _EFI_SECURITY2_PROTOCOL;
struct _EFI_SECURITY_PROTOCOL;
typedef struct _EFI_SECURITY2_PROTOCOL EFI_SECURITY2_PROTOCOL;
typedef struct _EFI_SECURITY_PROTOCOL EFI_SECURITY_PROTOCOL;
typedef EFI_DEVICE_PATH EFI_DEVICE_PATH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE) (
			const EFI_SECURITY_PROTOCOL *This,
			UINT32 AuthenticationStatus,
			const EFI_DEVICE_PATH_PROTOCOL *File
								     );
typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION) (
			const EFI_SECURITY2_PROTOCOL *This,
			const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
			VOID *FileBuffer,
			UINTN FileSize,
			BOOLEAN	BootPolicy
								     );

struct _EFI_SECURITY2_PROTOCOL {
	EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

struct _EFI_SECURITY_PROTOCOL {
	EFI_SECURITY_FILE_AUTHENTICATION_STATE  FileAuthenticationState;
};


static UINT8 *security_policy_esl = NULL;
static UINTN security_policy_esl_len;
static SecurityHook extra_check = NULL;

static EFI_SECURITY_FILE_AUTHENTICATION_STATE esfas = NULL;
static EFI_SECURITY2_FILE_AUTHENTICATION es2fa = NULL;

extern EFI_STATUS thunk_security_policy_authentication(
	const EFI_SECURITY_PROTOCOL *This,
	UINT32 AuthenticationStatus,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePath
						       )
__attribute__((unused));

extern EFI_STATUS thunk_security2_policy_authentication(
	const EFI_SECURITY2_PROTOCOL *This,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	VOID *FileBuffer,
	UINTN FileSize,
	BOOLEAN	BootPolicy
						       )
__attribute__((unused));

static __attribute__((used)) EFI_STATUS
security2_policy_authentication (
	const EFI_SECURITY2_PROTOCOL *This,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	VOID *FileBuffer,
	UINTN FileSize,
	BOOLEAN	BootPolicy
				 )
{
	/* Chain original security policy */

	es2fa(This, DevicePath, FileBuffer, FileSize, BootPolicy);
	
	return EFI_SUCCESS;
}

static __attribute__((used)) EFI_STATUS
security_policy_authentication (
	const EFI_SECURITY_PROTOCOL *This,
	UINT32 AuthenticationStatus,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePathConst
	)
{
	/* Chain original security policy */
	esfas(This, AuthenticationStatus, DevicePathConst);
	
	return EFI_SUCCESS;
}


/* Nasty: ELF and EFI have different calling conventions.  Here is the map for
 * calling ELF -> EFI
 *
 *   1) rdi -> rcx (32 saved)
 *   2) rsi -> rdx (32 saved)
 *   3) rdx -> r8 ( 32 saved)
 *   4) rcx -> r9 (32 saved)
 *   5) r8 -> 32(%rsp) (48 saved)
 *   6) r9 -> 40(%rsp) (48 saved)
 *   7) pad+0(%rsp) -> 48(%rsp) (64 saved)
 *   8) pad+8(%rsp) -> 56(%rsp) (64 saved)
 *   9) pad+16(%rsp) -> 64(%rsp) (80 saved)
 *  10) pad+24(%rsp) -> 72(%rsp) (80 saved)
 *  11) pad+32(%rsp) -> 80(%rsp) (96 saved)

 *
 * So for a five argument callback, the map is ignore the first two arguments
 * and then map (EFI -> ELF) assuming pad = 0.
 *
 * ARG4  -> ARG1
 * ARG3  -> ARG2
 * ARG5  -> ARG3
 * ARG6  -> ARG4
 * ARG11 -> ARG5
 *
 * Calling conventions also differ over volatile and preserved registers in
 * MS: RBX, RBP, RDI, RSI, R12, R13, R14, and R15 are considered nonvolatile .
 * In ELF: Registers %rbp, %rbx and %r12 through %r15 “belong” to the calling
 * function and the called function is required to preserve their values.
 *
 * This means when accepting a function callback from MS -> ELF, we have to do
 * separate preservation on %rdi, %rsi before swizzling the arguments and
 * handing off to the ELF function.
 */

asm (
".type security2_policy_authentication,@function\n"
"thunk_security2_policy_authentication:\n\t"

	"ret\n"
);

asm (
".type security_policy_authentication,@function\n"
"thunk_security_policy_authentication:\n\t"

	"ret\n"
);

EFI_STATUS
security_policy_install(SecurityHook hook)
{
	EFI_SECURITY_PROTOCOL *security_protocol;
	EFI_SECURITY2_PROTOCOL *security2_protocol = NULL;
	EFI_STATUS efi_status;

	if (esfas)
		/* Already Installed */
		return EFI_ALREADY_STARTED;

	/* Don't bother with status here.  The call is allowed
	 * to fail, since SECURITY2 was introduced in PI 1.2.1
	 * If it fails, use security2_protocol == NULL as indicator */
	LibLocateProtocol(&SECURITY2_PROTOCOL_GUID,
			  (VOID **) &security2_protocol);

	efi_status = LibLocateProtocol(&SECURITY_PROTOCOL_GUID,
				       (VOID **) &security_protocol);
	if (EFI_ERROR(efi_status))
		/* This one is mandatory, so there's a serious problem */
		return efi_status;

	if (security2_protocol) {
		es2fa = security2_protocol->FileAuthentication;
		security2_protocol->FileAuthentication =
			(EFI_SECURITY2_FILE_AUTHENTICATION) thunk_security2_policy_authentication;
	}

	esfas = security_protocol->FileAuthenticationState;
	security_protocol->FileAuthenticationState =
		(EFI_SECURITY_FILE_AUTHENTICATION_STATE) thunk_security_policy_authentication;

	if (hook)
		extra_check = hook;

	return EFI_SUCCESS;
}

EFI_STATUS
security_policy_uninstall(void)
{
	EFI_STATUS efi_status;

	if (esfas) {
		EFI_SECURITY_PROTOCOL *security_protocol;

		efi_status = LibLocateProtocol(&SECURITY_PROTOCOL_GUID,
					       (VOID **) &security_protocol);
		if (EFI_ERROR(efi_status))
			return efi_status;

		security_protocol->FileAuthenticationState = esfas;
		esfas = NULL;
	} else {
		/* nothing installed */
		return EFI_NOT_STARTED;
	}

	if (es2fa) {
		EFI_SECURITY2_PROTOCOL *security2_protocol;

		efi_status = LibLocateProtocol(&SECURITY2_PROTOCOL_GUID,
					       (VOID **) &security2_protocol);
		if (EFI_ERROR(efi_status))
			return efi_status;

		security2_protocol->FileAuthentication = es2fa;
		es2fa = NULL;
	}

	if (extra_check)
		extra_check = NULL;

	return EFI_SUCCESS;
}

void
security_protocol_set_hashes(unsigned char *esl, int len)
{
	security_policy_esl = esl;
	security_policy_esl_len = len;
}
#endif /* OVERRIDE_SECURITY_POLICY */
