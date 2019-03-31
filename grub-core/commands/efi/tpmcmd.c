#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/extcmd.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/term.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_efi_guid_t tpm_guid = EFI_TPM_GUID;
static grub_efi_guid_t tpm2_guid = EFI_TPM2_GUID;

static void
grub_tpm1_prettyprint_bscaps (TCG_EFI_BOOT_SERVICE_CAPABILITY *caps)
{
  grub_printf ("TCG Boot Service Capabilities:\n");
  grub_printf ("  Size: 0x%02x\n", caps->Size);
  grub_printf ("  StructureVersion:\n");
  grub_printf ("    Major: 0x%02x\n", caps->StructureVersion.Major);
  grub_printf ("    Minor: 0x%02x\n", caps->StructureVersion.Minor);
  grub_printf ("    RevMajor: 0x%02x\n", caps->StructureVersion.RevMajor);
  grub_printf ("    RevMinor: 0x%02x\n", caps->StructureVersion.RevMinor);
  grub_printf ("  ProtocolSpecVersion:\n");
  grub_printf ("    Major: 0x%02x\n", caps->ProtocolSpecVersion.Major);
  grub_printf ("    Minor: 0x%02x\n", caps->ProtocolSpecVersion.Minor);
  grub_printf ("    RevMajor: 0x%02x\n", caps->ProtocolSpecVersion.RevMajor);
  grub_printf ("    RevMinor: 0x%02x\n", caps->ProtocolSpecVersion.RevMinor);
  grub_printf ("  HashAlgorithmBitmap: 0x%08x\n", caps->HashAlgorithmBitmap);
  grub_printf ("  TPMPresentFlag: 0x%02x : %s\n",
    caps->TPMPresentFlag, (caps->TPMPresentFlag) ? "true" : "false");
  grub_printf ("  TPMDeactivatedFlag: 0x%02x : %s\n",
    caps->TPMDeactivatedFlag, (caps->TPMDeactivatedFlag) ? "true" : "false");
}

static grub_err_t
grub_tpm1_get_capability (grub_efi_tpm_protocol_t *tpm,
                          TCG_EFI_BOOT_SERVICE_CAPABILITY *caps)
{
  grub_efi_physical_address_t eventlog, lastevent;
  grub_efi_status_t status;
  grub_uint32_t flags;

  if (!grub_tpm1_present (tpm))
    return GRUB_ERR_NONE;

  status = efi_call_5 (tpm->status_check, tpm, caps, &flags, &eventlog,
		       &lastevent);
  switch (status) {
  case GRUB_EFI_SUCCESS:
    return GRUB_ERR_NONE;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}

static grub_err_t
grub_tpm1_print_bscaps (grub_efi_handle_t tpm_handle __attribute__ ((unused)))
{
  TCG_EFI_BOOT_SERVICE_CAPABILITY caps = { .Size = sizeof (caps), };
  grub_efi_tpm_protocol_t *tpm;
  grub_err_t err = GRUB_ERR_NONE;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  err = grub_tpm1_get_capability (tpm, &caps);
  if (err != GRUB_ERR_NONE)
      return err;

  grub_tpm1_prettyprint_bscaps (&caps);
  return GRUB_ERR_NONE;
}

static void
grub_tpm2_prettyprint_bscaps (EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps)
{
  grub_printf ("TGC2 Boot Service Capabilities:\n");
  grub_printf ("  Size: 0x%02x\n", caps->Size);
  grub_printf ("  StructureVersion:\n");
  grub_printf ("    Major: 0x%02x\n", caps->StructureVersion.Major);
  grub_printf ("    Minor: 0x%02x\n", caps->StructureVersion.Minor);
  grub_printf ("  ProtocolVersion:\n");
  grub_printf ("    Major: 0x%02x\n", caps->ProtocolVersion.Major);
  grub_printf ("    Minor: 0x%02x\n", caps->ProtocolVersion.Minor);
  grub_printf ("  HashAlgorithmBitmap: 0x%08x\n",
    caps->HashAlgorithmBitmap);
  grub_printf ("    EFI_TCG2_BOOT_HASH_ALG_SHA1: %s\n",
    (caps->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA1) ? "true" : "false");
  grub_printf ("    EFI_TCG2_BOOT_HASH_ALG_SHA256: %s\n",
    (caps->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA256) ? "true" : "false");
  grub_printf ("    EFI_TCG2_BOOT_HASH_ALG_SHA384: %s\n",
    (caps->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA384) ? "true" : "false");
  grub_printf ("    EFI_TCG2_BOOT_HASH_ALG_SHA512: %s\n",
    (caps->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA512) ? "true" : "false");
  grub_printf ("    EFI_TCG2_BOOT_HASH_ALG_SM3_256: %s\n",
    (caps->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SM3_256) ? "true" : "false");
  grub_printf ("  SupportedEventLogs: 0x%08x\n",
    caps->SupportedEventLogs);
  grub_printf ("    EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2: %s\n",
    (caps->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2) ? "true" : "false");
  grub_printf ("    EFI_TCG2_EVENT_LOG_FORMAT_TCG_2: %s\n",
    (caps->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_2) ? "true" : "false");
  grub_printf ("  TPMPresentFlag: 0x%02x : %s\n",
    caps->TPMPresentFlag, (caps->TPMPresentFlag) ? "true" : "false");
  grub_printf ("  MaxCommandSize: 0x%04x\n",
    caps->MaxCommandSize);
  grub_printf ("  MaxResponseSize: 0x%04x\n",
    caps->MaxResponseSize);
  grub_printf ("  ManufacturerID: 0x%08x\n",
    caps->ManufacturerID);
  grub_printf ("  NumberOfPcrBanks: 0x%08x\n",
    caps->NumberOfPcrBanks);
  grub_printf ("  ActivePcrBanks: 0x%08x\n",
    caps->ActivePcrBanks);
}

static grub_err_t
grub_tpm2_get_capability (grub_efi_tpm2_protocol_t *tpm,
                          EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps)
{
  grub_efi_status_t status;

  if (!grub_tpm2_present (tpm))
    return 0;

  status = efi_call_2 (tpm->get_capability, tpm, caps);
  switch (status) {
  case GRUB_EFI_SUCCESS:
    return GRUB_ERR_NONE;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Buffer too small"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}
static grub_err_t
grub_tpm2_print_bscaps (grub_efi_handle_t tpm_handle)
{
  EFI_TCG2_BOOT_SERVICE_CAPABILITY caps = { .Size = sizeof (caps), };
  grub_err_t err = GRUB_ERR_NONE;
  grub_efi_tpm2_protocol_t *tpm;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm2_present (tpm))
    return 0;
  err = grub_tpm2_get_capability (tpm, &caps);
  if (err != GRUB_ERR_NONE)
      return err;

  grub_tpm2_prettyprint_bscaps (&caps);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm_print_bootservices_caps (void)
{
  grub_efi_handle_t tpm_handle;
  grub_efi_uint8_t protocol_version;

  if (!grub_tpm_handle_find (&tpm_handle, &protocol_version)) {
    grub_printf ("TPM not present\n");
    return 0;
  }

  if (protocol_version == 1)
    return grub_tpm1_print_bscaps (tpm_handle);
  else
    return grub_tpm2_print_bscaps (tpm_handle);
}

static grub_err_t
grub_tpm_print_bootservices_capabilities (
    grub_extcmd_context_t ctx __attribute__ ((unused)),
    int argc __attribute__ ((unused)),
    char **args __attribute__ ((unused)))
{
    return grub_tpm_print_bootservices_caps ();
}

static grub_extcmd_t cmd_print_bscaps;
static const struct grub_arg_option opts_help[] =
  {
    { "help", 'h', 0, N_("display help message"), NULL, ARG_TYPE_NONE },
    { 0 }
  };

GRUB_MOD_INIT (tpmcmd)
{
  cmd_print_bscaps =
    grub_register_extcmd (N_("tpm-print-bscaps"),
                          grub_tpm_print_bootservices_capabilities,
                          GRUB_COMMAND_FLAG_EXTCMD,
                          N_("[-h]"),
                          N_("Pretty print TPM capability structure.\n"),
                          opts_help);
}
GRUB_MOD_FINI (tpmcmd)
{
  grub_unregister_extcmd (cmd_print_bscaps);
}
