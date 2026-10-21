__attribute__((import_module("env"), import_name("host_tick")))
extern int host_tick(int);
int use_tick(int n) { return host_tick(n) + 1; }
int bounce(int n) { return n <= 0 ? use_tick(n) : bounce(n - 1) + use_tick(n); }
