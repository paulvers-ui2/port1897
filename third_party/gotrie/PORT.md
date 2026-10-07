# gotrie (patched copy)

Copy of [celzero/gotrie](https://github.com/celzero/gotrie) at commit `a2756ab2f6bd`
(the version firestack pins), MPL-2.0. `main.go` is left out.

Change: the `syscall.Mmap`/`Munmap` calls in `trie/build.go` moved into
`trie/mmap_unix.go`, with `trie/mmap_windows.go` using `CreateFileMapping` /
`MapViewOfFile`, so the package builds on Windows. Meant to be offered upstream;
drop this copy and the `replace` in the root `go.mod` once it lands.
