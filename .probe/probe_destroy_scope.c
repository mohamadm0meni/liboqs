// SPDX-License-Identifier: MIT
//
// TEMPORARY INVESTIGATION PROBE -- NOT A FIX, NOT FOR MERGE.
//
// Reproduces, using only the liboqs public API, the call sequence that
// tests/fuzz_test_kem.c and tests/fuzz_test_sig.c perform inside
// LLVMFuzzerTestOneInput(): OQS_init(); <crypto op>; OQS_destroy(); repeated
// across iterations, because libFuzzer re-enters that function in one process.
//
// Usage: probe_destroy_scope kem <ALG-NAME>
//        probe_destroy_scope sig <ALG-NAME>
//
// Exit codes:
//   0  -- both iterations completed (library survives destroy-then-reuse)
//   77 -- the requested algorithm is not enabled in this build (cell skipped)
//   anything else -- the library terminated the process during iteration 2
//
// The process may also be killed inside liboqs by OQS_EXIT_IF_NULLPTR /
// OQS_OPENSSL_GUARD, in which case this program never reaches its own return.

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>

static void probe_randombytes(uint8_t *buf, size_t n) {
	// Deterministic, and available in OQS_EMBEDDED_BUILD cells where
	// OQS_randombytes_system() is compiled out.
	for (size_t i = 0; i < n; i++) {
		buf[i] = (uint8_t)((i * 7u) + 3u);
	}
}

static int kem_iteration(const char *alg, int n) {
	printf("--- kem iteration %d (%s) ---\n", n, alg);
	fflush(stdout);
	OQS_init();
	OQS_randombytes_custom_algorithm(&probe_randombytes);
	OQS_KEM *kem = OQS_KEM_new(alg);
	if (kem == NULL) {
		printf("NOT-ENABLED %s\n", alg);
		fflush(stdout);
		return 77;
	}
	uint8_t *pk = malloc(kem->length_public_key);
	uint8_t *sk = malloc(kem->length_secret_key);
	uint8_t *ct = malloc(kem->length_ciphertext);
	uint8_t *ss1 = malloc(kem->length_shared_secret);
	uint8_t *ss2 = malloc(kem->length_shared_secret);
	if (!pk || !sk || !ct || !ss1 || !ss2) {
		printf("ALLOC-FAILED\n");
		return 99;
	}
	printf("  keypair rc=%d\n", (int)OQS_KEM_keypair(kem, pk, sk));
	fflush(stdout);
	printf("  encaps  rc=%d\n", (int)OQS_KEM_encaps(kem, ct, ss1, pk));
	fflush(stdout);
	printf("  decaps  rc=%d\n", (int)OQS_KEM_decaps(kem, ss2, ct, sk));
	fflush(stdout);
	free(pk);
	free(sk);
	free(ct);
	free(ss1);
	free(ss2);
	OQS_KEM_free(kem);
	OQS_destroy();
	printf("  OQS_destroy() returned\n");
	fflush(stdout);
	return 0;
}

static int sig_iteration(const char *alg, int n) {
	printf("--- sig iteration %d (%s) ---\n", n, alg);
	fflush(stdout);
	OQS_init();
	OQS_randombytes_custom_algorithm(&probe_randombytes);
	OQS_SIG *sig = OQS_SIG_new(alg);
	if (sig == NULL) {
		printf("NOT-ENABLED %s\n", alg);
		fflush(stdout);
		return 77;
	}
	uint8_t *pk = malloc(sig->length_public_key);
	uint8_t *sk = malloc(sig->length_secret_key);
	uint8_t *s = malloc(sig->length_signature);
	size_t slen = 0;
	uint8_t msg[8] = {0};
	if (!pk || !sk || !s) {
		printf("ALLOC-FAILED\n");
		return 99;
	}
	printf("  keypair rc=%d\n", (int)OQS_SIG_keypair(sig, pk, sk));
	fflush(stdout);
	printf("  sign    rc=%d\n", (int)OQS_SIG_sign(sig, s, &slen, msg, sizeof msg, sk));
	fflush(stdout);
	printf("  verify  rc=%d\n", (int)OQS_SIG_verify(sig, msg, sizeof msg, s, slen, pk));
	fflush(stdout);
	free(pk);
	free(sk);
	free(s);
	OQS_SIG_free(sig);
	OQS_destroy();
	printf("  OQS_destroy() returned\n");
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s {kem|sig} <ALG-NAME>\n", argv[0]);
		return 2;
	}
	const char *kind = argv[1];
	const char *alg = argv[2];
	int is_kem = (kind[0] == 'k');

	printf("liboqs %s\n", OQS_version());
	fflush(stdout);

	int rc = is_kem ? kem_iteration(alg, 1) : sig_iteration(alg, 1);
	if (rc != 0) {
		return rc;
	}
	rc = is_kem ? kem_iteration(alg, 2) : sig_iteration(alg, 2);
	if (rc != 0) {
		return rc;
	}
	printf("SURVIVED both iterations\n");
	return 0;
}
