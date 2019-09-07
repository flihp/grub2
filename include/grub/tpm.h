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
 */

#ifndef GRUB_TPM_HEADER
#define GRUB_TPM_HEADER 1

#define GRUB_STRING_PCR 8
#define GRUB_BINARY_PCR 9

#define SHA1_DIGEST_SIZE 20

#define TPM_BASE     0x0
#define TPM_SUCCESS  TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)

#define TPM_TAG_RQU_COMMAND 0x00C1
#define TPM_ORD_Extend 0x14

/*
 * Log event types. These are spread out over 2 specs:
 * "TCG EFI Protocol Specification For TPM Family 1.1 or 1.2" and
 * "TCG PC Client Specific Implementation Specification for Conventional BIOS"
 */
#define EV_PREBOOT_CERT            0x0
#define EV_POST_CODE               0x1
#define EV_UNUSED                  0x2
#define EV_NO_ACTION               0x3
#define EV_SEPARATOR               0x4
#define EV_ACTION                  0x5
#define EV_EVENT_TAG               0x6
#define EV_S_CRTM_CONTENTS         0x7
#define EV_S_CRTM_VERSION          0x8
#define EV_CPU_MICROCODE           0x9
#define EV_PLATFORM_CONFIG_FLAGS   0xa
#define EV_TABLE_OF_DEVICES        0xb
#define EV_COMPACT_HASH            0xc
#define EV_IPL                     0xd
#define EV_IPL_PARTITION_DATA      0xe
#define EV_NONHOST_CODE            0xf
#define EV_NONHOST_CONFIG          0x10
#define EV_NONHOST_INFO            0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS 0x12


/* TCG_PassThroughToTPM Input Parameter Block. */
typedef struct
{
  grub_uint16_t IPBLength;
  grub_uint16_t Reserved1;
  grub_uint16_t OPBLength;
  grub_uint16_t Reserved2;
  grub_uint8_t  TPMOperandIn[1];
} GRUB_PACKED PassThroughToTPM_InputParamBlock;

/* TCG_PassThroughToTPM Output Parameter Block. */
typedef struct
{
  grub_uint16_t OPBLength;
  grub_uint16_t Reserved;
  grub_uint8_t  TPMOperandOut[1];
} GRUB_PACKED PassThroughToTPM_OutputParamBlock;

typedef struct
{
  grub_uint16_t tag;
  grub_uint32_t paramSize;
  grub_uint32_t ordinal;
  grub_uint32_t pcrNum;
  /* The 160 bit value representing the event to be recorded. */
  grub_uint8_t  inDigest[SHA1_DIGEST_SIZE];
} GRUB_PACKED ExtendIncoming;

/* TPM_Extend Outgoing Operand. */
typedef struct
{
  grub_uint16_t tag;
  grub_uint32_t paramSize;
  grub_uint32_t returnCode;
  /* The PCR value after execution of the command. */
  grub_uint8_t  outDigest[SHA1_DIGEST_SIZE];
} GRUB_PACKED ExtendOutgoing;

grub_err_t grub_tpm_measure (unsigned char *buf, grub_size_t size,
			     grub_uint8_t pcr, const char *description);
grub_err_t grub_tpm_init (void);
grub_err_t grub_tpm_execute (PassThroughToTPM_InputParamBlock *inbuf,
			     PassThroughToTPM_OutputParamBlock *outbuf);
grub_err_t grub_tpm_log_event (unsigned char *buf, grub_size_t size,
			       grub_uint8_t pcr, const char *description);

#endif
