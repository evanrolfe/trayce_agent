// go:build exclude

// Tracks the currently-in-progress TLSWrap member function's this pointer, i.e., the pointer to the TLSWrap object.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, void*);
  __uint(max_entries, 1024);
} active_TLSWrap_memfn_this SEC(".maps");

// This pair of probe functions are attached to TLSWrap member functions to cache the TLSWrap object
// pointer, so that the probes on their nested functions can retrieve the pointer.
int probe_entry_TLSWrap_memfn(struct pt_regs* ctx) {
  void* tls_wrap = (void*)PT_REGS_PARM1(ctx);
  uint64_t id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&active_TLSWrap_memfn_this, &id, &tls_wrap, BPF_ANY);
  return 0;
}

int probe_ret_TLSWrap_memfn(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&active_TLSWrap_memfn_this, &id);
  return 0;
}
