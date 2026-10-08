// mayhem/bag_input_guard.cc — harness-side input guard for both BAG fuzz targets.
//
// What it guards against
// ----------------------
// BAG::Metadata::Metadata() (api/bag_metadata.cpp) reads the /BAG_root/metadata
// dataset as one fixed-length string via H5::DataSet::read(H5std_string&, StrType).
// The HDF5 C++ library (H5::DataSet::p_read_fixed_len) then calls
// `new char[type_size * npoints + 1]`, where both factors come straight from the
// file's datatype and dataspace headers. A mutated header asks for petabytes
// (seen locally: 0xff000000002aae and 0x7b777f0000001a54 bytes). ASan aborts on
// that request with allocation-size-too-big before operator new can throw
// std::bad_alloc, so the fuzzer stops on an input that a normal build rejects
// with an exception (Dataset::open() catches it and returns nullptr).
//
// This is uncontrolled allocation from a declared size, not memory corruption.
// It was earlier hidden with a runtime allocator option. That is now forbidden:
// Mayhem alone owns the sanitizer options. Instead, this guard checks the
// declared size before BAG sees the input and skips inputs whose metadata
// string is larger than any real BAG metadata document could be.
//
// The same failure happens inside the HDF5 C library itself. H5C_protect()
// (metadata cache load, called from H5HL_protect / H5G__stab_lookup while a
// path is resolved) mallocs the data segment of a local heap ("HEAP") with
// the size written in the heap prefix. A mutated prefix asks for e.g.
// 0x14827f00010000b0 bytes. HDF5 checks for NULL and fails cleanly, but under
// ASan the malloc aborts first. A heap block must lie inside the file, so a
// declared size or address beyond the end of the input is invalid by
// construction: HDF5 rejects it, or reads only zero fill past end of file.
// The guard therefore scans the raw bytes for local-heap ("HEAP") and
// global-heap ("GCOL") prefixes and skips an input that declares a block
// larger than the input itself. No reachable BAG code is lost.
//
// How it hooks in
// ---------------
// build.sh compiles the upstream harness with
// -DLLVMFuzzerTestOneInput=BagUpstreamTestOneInput. This TU supplies the real
// LLVMFuzzerTestOneInput, runs the check, then calls the upstream entry point.
// Upstream sources are not edited. The check opens the input from memory (HDF5
// core driver + file image), so it writes no temp file. HDF5 error printing is
// suppressed only inside the check (H5E_BEGIN_TRY / H5E_END_TRY restore it).
// Any input the check cannot parse goes to BAG unchanged: BAG must handle it.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <hdf5.h>

extern "C" int BagUpstreamTestOneInput(const uint8_t *buf, size_t len);

namespace {

// BAG metadata is an ISO 19115 XML document, normally a few KiB to a few
// hundred KiB. 64 MiB is far above any real document and far below both
// ASan's maximum allocation size and libFuzzer's default 2 GiB malloc limit.
constexpr unsigned long long kMaxMetadataBytes = 64ull << 20;

// HDF5 "size of lengths" / "size of offsets" from the superblock (default 8).
void superblockSizes(const uint8_t *buf, size_t len, unsigned &sizeOffsets, unsigned &sizeLengths)
{
    static const uint8_t kSig[8] = {0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'};
    sizeOffsets = sizeLengths = 8;
    // The superblock is at 0, 512, 1024, 2048, ... (HDF5 file format spec).
    for (size_t at = 0; at + 16 <= len; at = at ? at * 2 : 512)
    {
        if (memcmp(buf + at, kSig, sizeof(kSig)) != 0)
            continue;
        const uint8_t version = buf[at + 8];
        if (version <= 1) { sizeOffsets = buf[at + 13]; sizeLengths = buf[at + 14]; }
        else              { sizeOffsets = buf[at + 9];  sizeLengths = buf[at + 10]; }
        return;
    }
}

uint64_t readLE(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

// Return true if a local-heap or global-heap prefix declares a block that
// cannot fit inside the input.
//   HEAP: sig(4) version(1)=0 reserved(3) data-size(L) free-list-off(L) data-addr(O)
//   GCOL: sig(4) version(1)=1 reserved(3) collection-size(L)
bool heapBlockOutOfFile(const uint8_t *buf, size_t len)
{
    unsigned so = 8, sl = 8;
    superblockSizes(buf, len, so, sl);
    if (so == 0 || so > 8 || sl == 0 || sl > 8)
        return false;  // nonsense superblock: HDF5 refuses it before any heap load

    for (size_t i = 0; i + 8 + 2 * sl + so <= len; ++i)
    {
        if (buf[i] == 'H' && memcmp(buf + i, "HEAP", 4) == 0 && buf[i + 4] == 0)
        {
            const uint64_t size = readLE(buf + i + 8, sl);
            const uint64_t addr = readLE(buf + i + 8 + 2 * sl, so);
            if (size > len || addr > len)
                return true;
        }
        else if (buf[i] == 'G' && memcmp(buf + i, "GCOL", 4) == 0 && buf[i + 4] == 1)
        {
            if (readLE(buf + i + 8, sl) > len)
                return true;
        }
    }
    return false;
}

// Return true if the input declares a /BAG_root/metadata dataset whose
// in-memory size is above kMaxMetadataBytes.
bool metadataTooLarge(const uint8_t *buf, size_t len)
{
    if (len == 0)
        return false;

    bool tooLarge = false;
    hid_t fapl = H5I_INVALID_HID, file = H5I_INVALID_HID;
    hid_t dset = H5I_INVALID_HID, type = H5I_INVALID_HID, space = H5I_INVALID_HID;

    H5E_BEGIN_TRY
    {
        fapl = H5Pcreate(H5P_FILE_ACCESS);
        if (fapl >= 0 &&
            H5Pset_fapl_core(fapl, 64 * 1024, /*backing_store=*/0) >= 0 &&
            H5Pset_file_locking(fapl, /*use_file_locking=*/0, /*ignore_when_disabled=*/1) >= 0 &&
            H5Pset_file_image(fapl, const_cast<uint8_t *>(buf), len) >= 0)
        {
            file = H5Fopen("bag-input-guard", H5F_ACC_RDONLY, fapl);
        }
        if (file >= 0)
            dset = H5Dopen2(file, "/BAG_root/metadata", H5P_DEFAULT);
        if (dset >= 0)
        {
            type = H5Dget_type(dset);
            space = H5Dget_space(dset);
        }
        if (type >= 0 && space >= 0)
        {
            const size_t elemSize = H5Tget_size(type);
            const hssize_t npoints = H5Sget_simple_extent_npoints(space);
            if (npoints > 0 && elemSize > 0)
            {
                const unsigned long long n = static_cast<unsigned long long>(npoints);
                tooLarge = n > kMaxMetadataBytes / elemSize;
            }
        }
        if (space >= 0) H5Sclose(space);
        if (type >= 0) H5Tclose(type);
        if (dset >= 0) H5Dclose(dset);
        if (file >= 0) H5Fclose(file);
        if (fapl >= 0) H5Pclose(fapl);
    }
    H5E_END_TRY

    return tooLarge;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (heapBlockOutOfFile(buf, len) || metadataTooLarge(buf, len))
        return 0;
    return BagUpstreamTestOneInput(buf, len);
}
