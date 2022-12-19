#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "basisu_containers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    uint32_t v = provider.ConsumeIntegral<uint32_t>();
    basisu::helpers::floor_log2i(v);
    return 0;
}
