/* grub shell commands for interacting with the TPM */

#include <grub/err.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/extcmd.h>
#include <grub/lib/hexdump.h>
#include <grub/tpm.h>

#ifndef NULL
# define NULL	((void *) 0)
#endif

/* why aren't these defined anywhere here */
#define TPM2_ALG_SHA                 (0x0004)
#define TPM2_ALG_SHA1                (0x0004)
#define TPM2_ALG_SHA256              (0x000B)
#define TPM2_ALG_SHA384              (0x000C)
#define TPM2_ALG_SHA512              (0x000D)
#define TPM2_ALG_SM3_256             (0x0012)

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

static grub_err_t
grub_tpm2_get_eventlog (grub_efi_handle_t tpm_handle,
                        EFI_TCG2_EVENT_LOG_FORMAT format,
                        grub_efi_physical_address_t *first,
                        grub_efi_physical_address_t *last,
                        grub_efi_boolean_t *truncated)
{
  grub_efi_tpm2_protocol_t *tpm;
  grub_efi_status_t status;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (!grub_tpm2_present (tpm))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM2 unavailable"));

  status = efi_call_5 (tpm->get_event_log, tpm, format, first, last, truncated);
  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_INVALID_PARAMETER:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
    default:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
    }
}


static grub_err_t
grub_tpm1_print_eventlog (grub_efi_handle_t tpm_handle)
{
  (void)tpm_handle;
  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     N_("TPM 1.2 eventlog format not yet supported."));
}

static grub_size_t
get_alg_size (grub_efi_uint16_t alg_id)
{
    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
    default:
        return 0;
    }
}

static grub_size_t
sizeof_digest2 (TPMT_HA *digest)
{
    return sizeof (*digest) + get_alg_size (digest->AlgorithmId);
}
static TPMT_HA*
get_next_digest (TPMT_HA *digest)
{
    return (TPMT_HA*)(digest->Digest + get_alg_size (digest->AlgorithmId));
}
static const char*
get_alg_name (grub_efi_uint16_t alg_id)
{
    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA1";
    case TPM2_ALG_SHA256:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA256";
    case TPM2_ALG_SHA384:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA384";
    case TPM2_ALG_SHA512:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA512";
    case TPM2_ALG_SM3_256:
        return "EFI_TCG2_BOOT_HASH_ALG_SM3_256";
    default:
        return "UNKNOWN_ALGORITHM";
    }
}
static void
prettyprint_tpm2_digest (TPMT_HA *digest)
{
    grub_size_t digest_size;

    grub_printf ("    AlgorithmId: %s (0x%x)\n",
           get_alg_name (digest->AlgorithmId), digest->AlgorithmId);
    /* map alg id to alg size to get buffer size */
    digest_size = get_alg_size (digest->AlgorithmId);
    grub_printf ("    Digest: %lu bytes\n", digest_size);
    hexdump (0, (char *)digest->Digest, digest_size);
}
static grub_err_t
prettyprint_tpm2_digest_callback (TPMT_HA *digest,
                                  void *data)
{
    grub_size_t *size = (grub_size_t*)data;

    prettyprint_tpm2_digest (digest);
    if (size) {
        *size += sizeof_digest2 (digest);
    }
    return GRUB_ERR_NONE;
}

typedef grub_err_t (*DIGEST2_CALLBACK) (TPMT_HA *digest,
                                        void *data);
static grub_err_t
foreach_digest2 (TCG_EVENT_HEADER2 *event_hdr,
                 DIGEST2_CALLBACK callback,
                 void *data)
{
    grub_err_t err = GRUB_ERR_NONE;

    TPMT_HA *digest = (TPMT_HA*)event_hdr->Digests;
    for (grub_size_t i = 0; i < event_hdr->DigestCount && digest != NULL; ++i) {
        err = callback (digest, data);
        if (err != GRUB_ERR_NONE)
            break;
        digest = get_next_digest (digest);
    }
    return err;
}

#ifndef FALSE
# define FALSE (0)
# define TRUE (!FALSE)
#endif

static grub_err_t
digest2_accumulator_callback (TPMT_HA *digest,
                              void *data)
{
    grub_size_t *size = (grub_size_t*)data;
    if (size == NULL)
        return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));

    *size += sizeof_digest2 (digest);
    return GRUB_ERR_NONE;
}
static TCG_EVENT_HEADER2*
get_next_event (TCG_EVENT_HEADER2 *event_hdr)
{
    grub_size_t digests_size = 0;
    grub_err_t err;
    TCG_EVENT2 *event;

    err = foreach_digest2 (event_hdr,
                           digest2_accumulator_callback,
                           &digests_size);
    if (err != GRUB_ERR_NONE)
        return NULL;
    event = (TCG_EVENT2*)((grub_efi_physical_address_t)event_hdr->Digests + digests_size);
    return (TCG_EVENT_HEADER2*)((grub_efi_physical_address_t)event->Event + event->EventSize);
}

typedef grub_err_t (*EVENT2_CALLBACK) (TCG_EVENT_HEADER2 *event_hdr,
                                       void *data);
static grub_err_t
foreach_event2 (TCG_EVENT_HEADER2 *event_first,
                TCG_EVENT_HEADER2 *event_last,
                EVENT2_CALLBACK callback,
                void *data)
{
    TCG_EVENT_HEADER2 *event;
    grub_err_t err;

    if (event_first == NULL || event_last == NULL || callback == NULL)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));

    for (event = event_first;
         event <= event_last && event != NULL;
         event = get_next_event (event))
    {
        err = callback (event, data);
        if (err != GRUB_ERR_NONE)
            return err;
    }
    return GRUB_ERR_NONE;
}
static const char*
eventtype_to_string (TCG_EVENTTYPE event_type)
{
    switch (event_type) {
    case EV_PREBOOT_CERT:
        return "EV_PREBOOT_CERT";
    case EV_POST_CODE:
        return "EV_POST_CODE";
    case EV_UNUSED:
        return "EV_UNUSED";
    case EV_NO_ACTION:
        return "EV_NO_ACTION";
    case EV_SEPARATOR:
        return "EV_SEPARATOR";
    case EV_ACTION:
        return "EV_ACTION";
    case EV_EVENT_TAG:
        return "EV_EVENT_TAG";
    case EV_S_CRTM_CONTENTS:
        return "EV_S_CRTM_CONTENTS";
    case EV_S_CRTM_VERSION:
        return "EV_S_CRTM_VERSION";
    case EV_CPU_MICROCODE:
        return "EV_CPU_MICROCODE";
    case EV_PLATFORM_CONFIG_FLAGS:
        return "EV_PLATFORM_CONFIG_FLAGS";
    case EV_TABLE_OF_DEVICES:
        return "EV_TABLE_OF_DEVICES";
    case EV_COMPACT_HASH:
        return "EV_COMPACT_HASH";
    case EV_IPL:
        return "EV_IPL";
    case EV_IPL_PARTITION_DATA:
        return "EV_IPL_PARTITION_DATA";
    case EV_NONHOST_CODE:
        return "EV_NONHOST_CODE";
    case EV_NONHOST_CONFIG:
        return "EV_NONHOST_CONFIG";
    case EV_NONHOST_INFO:
        return "EV_NONHOST_INFO";
    case EV_OMIT_BOOT_DEVICE_EVENTS:
        return "EV_OMIT_BOOT_DEVICE_EVENTS";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
        return "EV_EFI_VARIABLE_DRIVER_CONFIG";
    case EV_EFI_VARIABLE_BOOT:
        return "EV_EFI_VARIABLE_BOOT";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
        return "EV_EFI_BOOT_SERVICES_APPLICATION";
    case EV_EFI_BOOT_SERVICES_DRIVER:
        return "EV_EFI_BOOT_SERVICES_DRIVER";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return "EV_EFI_RUNTIME_SERVICES_DRIVER";
    case EV_EFI_GPT_EVENT:
        return "EV_EFI_GPT_EVENT";
    case EV_EFI_ACTION:
        return "EV_EFI_ACTION";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case EV_EFI_HANDOFF_TABLES:
        return "EV_EFI_HANDOFF_TABLES";
    case EV_EFI_VARIABLE_AUTHORITY:
        return "EV_EFI_VARIABLE_AUTHORITY";
    default:
        return "Unknown event type";
    }
}
static void
prettyprint_tpm2_event_header (TCG_EVENT_HEADER2 *event_hdr)
{
    grub_printf ("  PCRIndex: %d\n", event_hdr->PCRIndex);
    grub_printf ("  EventType: %s (0x%x)\n",
           eventtype_to_string (event_hdr->EventType),
           event_hdr->EventType);
    grub_printf ("  DigestCount: %d\n", event_hdr->DigestCount);
}
static void
prettyprint_tpm2_eventbuf (TCG_EVENT2 *event)
{
    grub_printf ("  Event: %u bytes\n", event->EventSize);
    hexdump (0, (char*)event->Event, event->EventSize);
}
static grub_err_t
prettyprint_tpm2_event (TCG_EVENT_HEADER2 *event_hdr)
{
    TCG_EVENT2 *event;
    grub_size_t digests_size = 0;
    grub_err_t err;

    if (event_hdr == NULL)
        return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));

    prettyprint_tpm2_event_header (event_hdr);
    err = foreach_digest2 (event_hdr,
                           prettyprint_tpm2_digest_callback,
                           &digests_size);
    if (err != GRUB_ERR_NONE)
        return err;
    event = (TCG_EVENT2*)((grub_efi_physical_address_t)event_hdr->Digests + digests_size);
    prettyprint_tpm2_eventbuf (event);
    return GRUB_ERR_NONE;
}
static grub_err_t
prettyprint_tpm2_event_callback (TCG_EVENT_HEADER2 *event_hdr,
                                 void *data)
{
    grub_size_t *event_count = (grub_size_t*)data;

    grub_printf ("Event[%lu]:\n", *event_count);
    ++(*event_count);
    return prettyprint_tpm2_event (event_hdr);
}
static grub_err_t
grub_tpm2_print_eventlog (grub_efi_handle_t tpm_handle)
{
  grub_err_t err = GRUB_ERR_NONE;
  grub_efi_physical_address_t first, last;
  grub_efi_boolean_t truncated = FALSE;
  grub_size_t event_count = 0;

  err = grub_tpm2_get_eventlog (tpm_handle,
                                EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
                                &first,
                                &last,
                                &truncated);
  if (err != GRUB_ERR_NONE)
      return err;

  if (truncated)
    grub_printf ("WARNING: TPM EventLog has been truncated.\n");
  return foreach_event2 ((TCG_EVENT_HEADER2*)first,
                         (TCG_EVENT_HEADER2*)last,
                         prettyprint_tpm2_event_callback,
                         &event_count);
}

/* prettyprint highest supported eventlog */
static grub_err_t
grub_tpm_print_eventlog (
    grub_extcmd_context_t ctx __attribute__ ((unused)),
    int argc __attribute__ ((unused)),
    char **args __attribute__ ((unused)))
{
  grub_efi_handle_t tpm_handle;
  grub_efi_uint8_t protocol_version;

  if (!grub_tpm_handle_find (&tpm_handle, &protocol_version))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));

  if (protocol_version == 1) {
    return grub_tpm1_print_eventlog (tpm_handle);
  } else {
    /* tpm2 supports both 1.2 and 2.0 eventlog formats */
    return grub_tpm2_print_eventlog (tpm_handle);
  }
}

static grub_extcmd_t cmd_print_bscaps;
static grub_extcmd_t cmd_print_eventlog;

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
  cmd_print_eventlog =
    grub_register_extcmd (N_("tpm-print-eventlog"),
                          grub_tpm_print_eventlog,
                          GRUB_COMMAND_FLAG_EXTCMD,
                          N_("[-h]"),
                          N_("Pretty print TPM capability structure.\n"),
                          opts_help);
}
GRUB_MOD_FINI (tpmcmd)
{
  grub_unregister_extcmd (cmd_print_bscaps);
}
