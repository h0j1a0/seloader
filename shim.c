// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright Red Hat, Inc
 * Author: Matthew Garrett
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#include "shim.h"
#include <stdint.h>

#define OID_EKU_MODSIGN "1.3.6.1.4.1.2312.16.1.2"

static EFI_SYSTEM_TABLE *systab;
static EFI_HANDLE global_image_handle;
static EFI_LOADED_IMAGE *shim_li;
static EFI_LOADED_IMAGE shim_li_bak;

list_t sbat_var;

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

/*
 * Check whether we're in Secure Boot and user mode
 */
BOOLEAN secure_mode (void)
{
	if (user_insecure_mode)
		return FALSE;

	if (variable_is_secureboot() != 1) {
		return FALSE;
	}

	/* If we /do/ have "SecureBoot", but /don't/ have "SetupMode",
	 * then the implementation is bad, but we assume that secure boot is
	 * enabled according to the status of "SecureBoot".  If we have both
	 * of them, then "SetupMode" may tell us additional data, and we need
	 * to consider it.
	 */
	if (variable_is_setupmode(0) == 1) {
		return FALSE;
	}
	
	return TRUE;
}

/*
 * Check that the signature is valid and matches the binary and that
 * the binary is permitted to load by SBAT.
 */
EFI_STATUS
verify_buffer (char *data, int datasize,
	       PE_COFF_LOADER_IMAGE_CONTEXT *context,
	       UINT8 *sha256hash, UINT8 *sha1hash)
{
	generate_hash(data, datasize, context, sha256hash, sha1hash);

	return EFI_SUCCESS;
}

/*
 * Open the second stage bootloader and read it into a buffer
 */
static EFI_STATUS load_image (EFI_LOADED_IMAGE *li, void **data,
			      int *datasize, CHAR16 *PathName)
{
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_FILE_INFO *fileinfo = NULL;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root, *grub;
	UINTN buffersize = sizeof(EFI_FILE_INFO);

	device = li->DeviceHandle;

	dprint(L"attempting to load %s\n", PathName);
	/*
	 * Open the device
	 */
	efi_status = BS->HandleProtocol(device, &EFI_SIMPLE_FILE_SYSTEM_GUID,
					(void **) &drive);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to find fs: %r\n", efi_status);
		goto error;
	}

	efi_status = drive->OpenVolume(drive, &root);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open fs: %r\n", efi_status);
		goto error;
	}

	/*
	 * And then open the file
	 */
	efi_status = root->Open(root, &grub, PathName, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open %s - %r\n", PathName, efi_status);
		goto error;
	}

	fileinfo = AllocatePool(buffersize);

	if (!fileinfo) {
		perror(L"Unable to allocate file info buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Find out how big the file is in order to allocate the storage
	 * buffer
	 */
	efi_status = grub->GetInfo(grub, &EFI_FILE_INFO_GUID, &buffersize,
				   fileinfo);
	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(fileinfo);
		fileinfo = AllocatePool(buffersize);
		if (!fileinfo) {
			perror(L"Unable to allocate file info buffer\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto error;
		}
		efi_status = grub->GetInfo(grub, &EFI_FILE_INFO_GUID,
					   &buffersize, fileinfo);
	}

	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to get file info: %r\n", efi_status);
		goto error;
	}

	buffersize = fileinfo->FileSize;
	*data = AllocatePool(buffersize);
	if (!*data) {
		perror(L"Unable to allocate file buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Perform the actual read
	 */
	efi_status = grub->Read(grub, &buffersize, *data);
	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(buffersize);
		efi_status = grub->Read(grub, &buffersize, *data);
	}
	if (EFI_ERROR(efi_status)) {
		perror(L"Unexpected return from initial read: %r, buffersize %x\n",
		       efi_status, buffersize);
		goto error;
	}

	*datasize = buffersize;

	FreePool(fileinfo);

	return EFI_SUCCESS;
error:
	if (*data) {
		FreePool(*data);
		*data = NULL;
	}

	if (fileinfo)
		FreePool(fileinfo);
	return efi_status;
}

VOID
restore_loaded_image(VOID)
{
	if (shim_li->FilePath)
		FreePool(shim_li->FilePath);

	/*
	 * Restore our original loaded image values
	 */
	CopyMem(shim_li, &shim_li_bak, sizeof(shim_li_bak));
}

/*
 * Load and run an EFI executable
 */
EFI_STATUS read_image(EFI_HANDLE image_handle, CHAR16 *ImagePath,
		      CHAR16 **PathName, void **data, int *datasize)
{
	EFI_STATUS efi_status;

	/*
	 * We need to refer to the loaded image protocol on the running
	 * binary in order to find our path
	 */
	efi_status = BS->HandleProtocol(image_handle, &EFI_LOADED_IMAGE_GUID,
					(void **)&shim_li);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to init protocol\n");
		return efi_status;
	}

	/*
	 * Build a new path from the existing one plus the executable name
	 */
	efi_status = generate_path_from_image_path(shim_li, ImagePath, PathName);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to generate path %s: %r\n", ImagePath,
		       efi_status);
		return efi_status;
	}

		/*
		 * Read the new executable off disk
		 */
		efi_status = load_image(shim_li, data, datasize, *PathName);
		if (EFI_ERROR(efi_status)) {
			perror(L"Failed to load image %s: %r\n",
			       PathName, efi_status);
			PrintErrors();
			ClearErrors();
			return efi_status;
		}

	if (*datasize < 0)
		efi_status = EFI_INVALID_PARAMETER;

	return efi_status;
}

/*
 * Load and run an EFI executable
 */
EFI_STATUS start_image(EFI_HANDLE image_handle, CHAR16 *ImagePath)
{
	EFI_STATUS efi_status;
	EFI_IMAGE_ENTRY_POINT entry_point;
	EFI_PHYSICAL_ADDRESS alloc_address;
	UINTN alloc_pages;
	CHAR16 *PathName = NULL;
	void *data = NULL;
	int datasize = 0;

	efi_status = read_image(image_handle, ImagePath, &PathName, &data,
				&datasize);
	if (EFI_ERROR(efi_status))
		goto done;

	/*
	 * We need to modify the loaded image protocol entry before running
	 * the new binary, so back it up
	 */
	CopyMem(&shim_li_bak, shim_li, sizeof(shim_li_bak));

	/*
	 * Update the loaded image with the second stage loader file path
	 */
	shim_li->FilePath = FileDevicePath(NULL, PathName);
	if (!shim_li->FilePath) {
		perror(L"Unable to update loaded image file path\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto restore;
	}

	/*
	 * Verify and, if appropriate, relocate and execute the executable
	 */
	efi_status = handle_image(data, datasize, shim_li, &entry_point,
				  &alloc_address, &alloc_pages);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to load image: %r\n", efi_status);
		PrintErrors();
		ClearErrors();
		goto restore;
	}

	loader_is_participating = 0;

	/*
	 * The binary is trusted and relocated. Run it
	 */
	efi_status = entry_point(image_handle, systab);

restore:
	restore_loaded_image();
done:
	if (PathName)
		FreePool(PathName);

	if (data)
		FreePool(data);

	return efi_status;
}

/*
 * Load and run grub. If that fails because grub isn't trusted, load and
 * run MokManager.
 */
EFI_STATUS init_grub(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;

		efi_status = start_image(image_handle, DEFAULT_LOADER);

	if (EFI_ERROR(efi_status)) {
		console_print(L"start_image() returned %r\n", efi_status);
		usleep(2000000);
	}

	return efi_status;
}

EFI_STATUS
install_shim_protocols(void)
{
#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Install the security protocol hook
	 */
	security_policy_install(EFI_SUCCESS);
#endif

	return EFI_SUCCESS;
}

void
uninstall_shim_protocols(void)
{
#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Clean up the security protocol hook
	 */
	security_policy_uninstall();
#endif
}

EFI_STATUS
shim_init(void)
{
	EFI_STATUS efi_status;

	dprint(L"%a", shim_version);

	efi_status = install_shim_protocols();
	if (EFI_ERROR(efi_status))
		perror(L"install_shim_protocols() failed: %r\n", efi_status);

	return efi_status;
}

void
shim_fini(void)
{
	/*
	 * Remove our protocols
	 */
	uninstall_shim_protocols();

	console_fini();
}

extern EFI_STATUS
efi_main(EFI_HANDLE passed_image_handle, EFI_SYSTEM_TABLE *passed_systab);

typedef enum {
	COLD_RESET,
	EXIT_FAILURE,
	EXIT_SUCCESS,	// keep this one last
} devel_egress_action;

void
devel_egress(devel_egress_action action UNUSED)
{
#ifdef ENABLE_SHIM_DEVEL
	char *reasons[] = {
		[COLD_RESET] = "reset",
		[EXIT_FAILURE] = "exit",
	};
	if (action == EXIT_SUCCESS)
		return;

	console_print(L"Waiting to %a...", reasons[action]);
	for (size_t sleepcount = 0; sleepcount < 10; sleepcount++) {
		console_print(L"%d...", 10 - sleepcount);
		usleep(1000000);
	}
	console_print(L"\ndoing %a\n", action);

	if (action == COLD_RESET)
		RT->ResetSystem(EfiResetCold, EFI_SECURITY_VIOLATION, 0, NULL);
#endif
}

EFI_STATUS
efi_main (EFI_HANDLE passed_image_handle, EFI_SYSTEM_TABLE *passed_systab)
{
	EFI_STATUS efi_status;
	EFI_HANDLE image_handle;

	systab = passed_systab;
	image_handle = global_image_handle = passed_image_handle;

	/*
	 * Ensure that gnu-efi functions are available
	 */
	InitializeLib(image_handle, systab);
	setup_verbosity();

	efi_status = shim_init();
	if (EFI_ERROR(efi_status)) {
		console_print(L"shim_init() failed");
	}

	/*
	 * Hand over control to the second stage bootloader
	 */
	efi_status = init_grub(image_handle);

	shim_fini();
	devel_egress(EFI_ERROR(efi_status) ? EXIT_FAILURE : EXIT_SUCCESS);
	return efi_status;
}
