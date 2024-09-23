// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// Test eBPF program for EBPF_PROGRAM_TYPE_FILE_OPS implemented in
// the eBPF FS Filter extension.

#include "bpf_helpers.h"
#include "file_ops_helpers.h"

#define ef_ext_helper_function1 ((sample_ebpf_extension_helper_function1_t)SAMPLE_EXT_HELPER_FN_BASE + 1)

SEC("file_ops")
int
test_program_entry(ef_program_context_t* context)
{
    int64_t result;
    result = ef_ext_helper_function1(context);
    if (result < 0) {
        goto Exit;
    }

    // "The answer to the question of life, the universe and everything".
    //          - Douglas Adams (The Hitchhiker’s Guide to the Galaxy).
    result = 42;
Exit:
    return result;
}
