/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2018  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  EFI TPM support code.
 */

#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/term.h>

typedef TCG_PCR_EVENT grub_tpm_event_t;

static grub_efi_guid_t tpm_guid = EFI_TPM_GUID;
static grub_efi_guid_t tpm2_guid = EFI_TPM2_GUID;

static grub_efi_handle_t *grub_tpm_handle;
static grub_uint8_t grub_tpm_version;

static grub_int8_t tpm1_present = -1;
static grub_int8_t tpm2_present = -1;

static grub_efi_boolean_t
grub_tpm1_present (grub_efi_tpm_protocol_t *tpm)
{
  grub_efi_status_t status;
  TCG_EFI_BOOT_SERVICE_CAPABILITY caps;
  grub_uint32_t flags;
  grub_efi_physical_address_t eventlog, lastevent;

  if (tpm1_present != -1)
    return (grub_efi_boolean_t) tpm1_present;

  caps.Size = (grub_uint8_t) sizeof (caps);

  status = efi_call_5 (tpm->status_check, tpm, &caps, &flags, &eventlog,
		       &lastevent);

  if (status != GRUB_EFI_SUCCESS || caps.TPMDeactivatedFlag
      || !caps.TPMPresentFlag)
    return tpm1_present = 0;

  return tpm1_present = 1;
}

static grub_efi_boolean_t
grub_tpm2_present (grub_efi_tpm2_protocol_t *tpm)
{
  grub_efi_status_t status;
  EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;

  caps.Size = (grub_uint8_t) sizeof (caps);

  if (tpm2_present != -1)
    return (grub_efi_boolean_t) tpm2_present;

  status = efi_call_2 (tpm->get_capability, tpm, &caps);

  if (status != GRUB_EFI_SUCCESS || !caps.TPMPresentFlag)
    return tpm2_present = 0;

  return tpm2_present = 1;
}

static grub_efi_boolean_t
grub_tpm_handle_find (grub_efi_handle_t *tpm_handle,
		      grub_efi_uint8_t *protocol_version)
{
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;

  if (grub_tpm_handle != NULL)
    {
      *tpm_handle = grub_tpm_handle;
      *protocol_version = grub_tpm_version;
      return 1;
    }

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL,
				    &num_handles);
  if (handles && num_handles > 0)
    {
      grub_tpm_handle = handles[0];
      *tpm_handle = handles[0];
      grub_tpm_version = 1;
      *protocol_version = 1;
      return 1;
    }

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm2_guid, NULL,
				    &num_handles);
  if (handles && num_handles > 0)
    {
      grub_tpm_handle = handles[0];
      *tpm_handle = handles[0];
      grub_tpm_version = 2;
      *protocol_version = 2;
      return 1;
    }

  return 0;
}

static grub_err_t
grub_tpm1_execute (grub_efi_handle_t tpm_handle,
                   PassThroughToTPM_InputParamBlock *inbuf,
                   PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_status_t status;
  grub_efi_tpm_protocol_t *tpm;
  grub_uint32_t inhdrsize = sizeof (*inbuf) - sizeof (inbuf->TPMOperandIn);
  grub_uint32_t outhdrsize =
    sizeof (*outbuf) - sizeof (outbuf->TPMOperandOut);

  tpm = grub_efi_open_protocol (tpm_handle, &tpm_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm1_present (tpm))
    return 0;

  /* UEFI TPM protocol takes the raw operand block, no param block header. */
  status = efi_call_5 (tpm->pass_through_to_tpm, tpm,
		       inbuf->IPBLength - inhdrsize, inbuf->TPMOperandIn,
		       outbuf->OPBLength - outhdrsize, outbuf->TPMOperandOut);

  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_DEVICE_ERROR:
      return grub_error (GRUB_ERR_IO, N_("Command failed"));
    case GRUB_EFI_INVALID_PARAMETER:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
    case GRUB_EFI_BUFFER_TOO_SMALL:
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("Output buffer too small"));
    case GRUB_EFI_NOT_FOUND:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
    default:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
    }
}

static grub_err_t
grub_tpm2_execute (grub_efi_handle_t tpm_handle,
                   PassThroughToTPM_InputParamBlock *inbuf,
                   PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;
  grub_uint32_t inhdrsize = sizeof (*inbuf) - sizeof (inbuf->TPMOperandIn);
  grub_uint32_t outhdrsize =
    sizeof (*outbuf) - sizeof (outbuf->TPMOperandOut);

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm2_present (tpm))
    return 0;

  /* UEFI TPM protocol takes the raw operand block, no param block header. */
  status = efi_call_5 (tpm->submit_command, tpm,
		       inbuf->IPBLength - inhdrsize, inbuf->TPMOperandIn,
		       outbuf->OPBLength - outhdrsize, outbuf->TPMOperandOut);

  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_DEVICE_ERROR:
      return grub_error (GRUB_ERR_IO, N_("Command failed"));
    case GRUB_EFI_INVALID_PARAMETER:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
    case GRUB_EFI_BUFFER_TOO_SMALL:
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("Output buffer too small"));
    case GRUB_EFI_NOT_FOUND:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
    default:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
    }
}

grub_err_t
grub_tpm_execute (PassThroughToTPM_InputParamBlock *inbuf,
		  PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_handle_t tpm_handle;
  grub_uint8_t protocol_version;

  /* Absence of a TPM isn't a failure. */
  if (!grub_tpm_handle_find (&tpm_handle, &protocol_version))
    return 0;

  if (protocol_version == 1)
    return grub_tpm1_execute (tpm_handle, inbuf, outbuf);
  else
    return grub_tpm2_execute (tpm_handle, inbuf, outbuf);
}

static grub_err_t
grub_tpm1_log_event (grub_efi_handle_t tpm_handle, unsigned char *buf,
		     grub_size_t size, grub_uint8_t pcr,
		     const char *description)
{
  grub_tpm_event_t *event;
  grub_efi_status_t status;
  grub_efi_tpm_protocol_t *tpm;
  grub_efi_physical_address_t lastevent;
  grub_uint32_t algorithm;
  grub_uint32_t eventnum = 0;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm1_present (tpm))
    return 0;

  event = grub_zalloc (sizeof (*event) + grub_strlen (description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TPM event buffer"));

  event->PCRIndex = pcr;
  event->EventType = EV_IPL;
  event->EventSize = grub_strlen (description) + 1;
  grub_memcpy (event->Event, description, event->EventSize);

  algorithm = TCG_ALG_SHA;
  status = efi_call_7 (tpm->log_extend_event, tpm, buf, (grub_uint64_t) size,
		       algorithm, event, &eventnum, &lastevent);

  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_DEVICE_ERROR:
      return grub_error (GRUB_ERR_IO, N_("Command failed"));
    case GRUB_EFI_INVALID_PARAMETER:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
    case GRUB_EFI_BUFFER_TOO_SMALL:
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("Output buffer too small"));
    case GRUB_EFI_NOT_FOUND:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
    default:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
    }
}

static grub_err_t
grub_tpm2_log_event (grub_efi_handle_t tpm_handle, unsigned char *buf,
		     grub_size_t size, grub_uint8_t pcr,
		     const char *description)
{
  EFI_TCG2_EVENT *event;
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm2_present (tpm))
    return 0;

  event =
    grub_zalloc (sizeof (EFI_TCG2_EVENT) + grub_strlen (description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TPM event buffer"));

  event->Header.HeaderSize = sizeof (EFI_TCG2_EVENT_HEADER);
  event->Header.HeaderVersion = 1;
  event->Header.PCRIndex = pcr;
  event->Header.EventType = EV_IPL;
  event->Size =
    sizeof (*event) - sizeof (event->Event) + grub_strlen (description) + 1;
  grub_memcpy (event->Event, description, grub_strlen (description) + 1);

  status = efi_call_5 (tpm->hash_log_extend_event, tpm, 0, buf,
		       (grub_uint64_t) size, event);

  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_DEVICE_ERROR:
      return grub_error (GRUB_ERR_IO, N_("Command failed"));
    case GRUB_EFI_INVALID_PARAMETER:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
    case GRUB_EFI_BUFFER_TOO_SMALL:
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("Output buffer too small"));
    case GRUB_EFI_NOT_FOUND:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
    default:
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
    }
}

grub_err_t
grub_tpm_log_event (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		    const char *description)
{
  grub_efi_handle_t tpm_handle;
  grub_efi_uint8_t protocol_version;

  if (!grub_tpm_handle_find (&tpm_handle, &protocol_version))
    return 0;

  if (protocol_version == 1)
    return grub_tpm1_log_event (tpm_handle, buf, size, pcr, description);
  else
    return grub_tpm2_log_event (tpm_handle, buf, size, pcr, description);
}

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
grub_tpm1_get_bootservice_capability (grub_efi_tpm_protocol_t *tpm,
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
  err = grub_tpm1_get_bootservice_capability (tpm, &caps);
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
grub_tpm2_get_bootservice_capability (grub_efi_tpm2_protocol_t *tpm,
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
  err = grub_tpm2_get_bootservice_capability (tpm, &caps);
  if (err != GRUB_ERR_NONE)
      return err;

  grub_tpm2_prettyprint_bscaps (&caps);
  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm_print_bootservice_caps (void)
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
