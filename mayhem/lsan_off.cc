// mayhem/lsan_off.cc — turn LeakSanitizer off at build time for every ASan fuzz binary.
//
// -fsanitize=address always bundles LeakSanitizer. Leaks are not the bug class this
// campaign fuzzes for, and HDF5/libxml2 keep process-lifetime caches that LSan would
// report at exit. The LSan runtime calls this hook and skips leak checking when it
// returns non-zero. ASan memory-error checks and UBSan stay on and halting.
extern "C" int __lsan_is_turned_off() { return 1; }
