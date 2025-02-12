/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "tfm_builtin_key_ids.h"
#include "utils.h"
#include <Driver_Common.h>
#include <boards/pico2.h>
#include <cmsis_compiler.h> // IWYU pragma: keep
#include <hardware/uart.h>
#include <mbedtls/build_info.h>
#include <microrl/microrl.h>
#include <pico/stdio.h>
#include <pico/stdio_uart.h>
#include <psa/client.h>
#include <psa/crypto.h>
#include <psa/framework_feature.h>
#include <psa/initial_attestation.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tfm_plat_ns.h>

/**
 * \brief Platform peripherals and devices initialization.
 *        Can be overridden for platform specific initialization.
 *
 * \return  ARM_DRIVER_OK if the initialization succeeds
 */
__WEAK int32_t tfm_ns_platform_init(void) {
  __enable_irq();
  stdio_uart_init_full(uart0, 115200, 0, 1);

  return ARM_DRIVER_OK;
}

static int mrl_print(microrl_t *mrl, const char *str) {
  MICRORL_UNUSED(mrl);
  return printf("%s", str);
}

static void mrl_attest_cmd(int argc, const char *const *argv) {
  if (argc != 1) {
    puts("usage: attest <hex_encoded_challenge>");
    return;
  }

  const char *hex_challenge = argv[0];
  size_t hex_len = strlen(hex_challenge);
  if (hex_len % 2 != 0) {
    puts("invalid hex string length");
    return;
  }

  size_t challenge_len = hex_len / 2;
  uint8_t *challenge = malloc(challenge_len);
  if (!challenge) {
    puts("failed to allocate memory for challenge");
    goto challenge_cleanup;
  }

  for (size_t i = 0; i < challenge_len; i++) {
    char high_nibble = hex_challenge[i * 2];
    char low_nibble = hex_challenge[i * 2 + 1];
    challenge[i] =
        ((high_nibble >= '0' && high_nibble <= '9') ? (high_nibble - '0')
                                                    : (high_nibble - 'a' + 10))
        << 4;
    challenge[i] |= (low_nibble >= '0' && low_nibble <= '9')
                        ? (low_nibble - '0')
                        : (low_nibble - 'a' + 10);
  }
  printf("attesting with challenge `%s` (len=%d)\n", hex_challenge,
         challenge_len);

  size_t token_len;
  psa_status_t err =
      psa_initial_attest_get_token_size(challenge_len, &token_len);
  if (err != PSA_SUCCESS) {
    printf("psa_initial_attest_get_token_size failed: %d\n", err);
    goto challenge_cleanup;
  }
  uint8_t *token = malloc(token_len);
  printf("presumed token size %d\n", token_len);
  if (!token) {
    puts("failed to allocate token");
    goto challenge_cleanup;
  }

  size_t actual_token_len;
  err = psa_initial_attest_get_token((const uint8_t *)challenge, challenge_len,
                                     token, token_len, &actual_token_len);
  if (err != PSA_SUCCESS) {
    printf("psa_initial_attest_get_token failed: %d\n", err);
    goto token_cleanup;
  }

  print_buf_hex("initial attestation token", token, actual_token_len);
token_cleanup:
  free(token);
challenge_cleanup:
  free(challenge);
}

static void mrl_version_cmd(int argc, const char *const *argv) {
  MICRORL_UNUSED(argc);
  MICRORL_UNUSED(argv);

  puts(MICRORL_COLOR_BLUE
       "####### Software Versions  #######" MICRORL_COLOR_DEFAULT);
  printf("Built with GCC:  v%d.%d.%d\n", __GNUC__, __GNUC_MINOR__,
         __GNUC_PATCHLEVEL__);
  puts("MbedTLS:         v" MBEDTLS_VERSION_STRING);
  uint32_t fw_version = psa_framework_version();
  printf("PSA Framework:   v%d.%d\n", fw_version >> 8, fw_version & 0xFF);
  printf("Attestation API: v%d.%d\n", PSA_INITIAL_ATTEST_API_VERSION_MAJOR,
         PSA_INITIAL_ATTEST_API_VERSION_MINOR);
}

static void mrl_info_cmd(int argc, const char *const *argv) {
  MICRORL_UNUSED(argc);
  MICRORL_UNUSED(argv);

  puts(MICRORL_COLOR_BLUE
       "####### System Information #######" MICRORL_COLOR_DEFAULT);
  printf("TF-M isolation level %d\n", PSA_FRAMEWORK_ISOLATION_LEVEL);

  uint8_t pubkey[65];
  size_t pubkey_len;
  psa_status_t err = psa_export_public_key(TFM_BUILTIN_KEY_ID_IAK, pubkey,
                                           sizeof(pubkey), &pubkey_len);
  if (err != PSA_SUCCESS) {
    printf("psa_export_public_key failed: %d\n", err);
    return;
  }

  print_buf_hex("IAK public key", pubkey + 1,
                pubkey_len - 1); // P256 keys always start with 0x04, strip it
}

static void mrl_help_cmd(int argc, const char *const *argv);

typedef void (*mrl_cmd_fn)(int argc, const char *const *argv);
typedef struct {
  mrl_cmd_fn fn;
  const char *name;
} mrl_cmd;
static const mrl_cmd mrl_cmds[] = {{mrl_attest_cmd, "attest"},
                                   {mrl_help_cmd, "help"},
                                   {mrl_version_cmd, "version"},
                                   {mrl_info_cmd, "info"},
                                   {0, 0}};

static void mrl_help_cmd(int argc, const char *const *argv) {
  puts("Available commands:");
  const mrl_cmd *cmd = mrl_cmds;
  while (cmd->name != 0) {
    putchar('\t');
    puts(cmd->name);
    cmd++;
  }
}

static int mrl_execute(microrl_t *mrl, int argc, const char *const *argv) {
  if (argc < 1) {
    return 0;
  }

  const mrl_cmd *cmd = mrl_cmds;

  while (cmd->name != 0) {
    if (strcmp(cmd->name, argv[0]) == 0) {
      cmd->fn(argc - 1, argv + 1);
      return 0;
    }
    cmd++;
  }

  printf("command not found: `%s`\n", argv[0]);

  return 0;
}

/**
 * \brief main() function
 */
#ifndef __GNUC__
__attribute__((noreturn))
#endif
int main(void)
{
  if (tfm_ns_platform_init() != ARM_DRIVER_OK) {
    /* Avoid undefined behavior if platform init failed */
    while (1)
      ;
  }

  printf("Non-Secure system starting...\n");
  printf("Hello TF-M world\r\n");

  mrl_info_cmd(0, NULL);
  mrl_version_cmd(0, NULL);

  microrl_t rl;
  microrl_init(&rl, mrl_print, mrl_execute);

  for (;;) {
    char c = getchar();
    microrl_processing_input(&rl, &c, 1);
  }
}
