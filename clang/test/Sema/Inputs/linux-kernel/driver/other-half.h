// What a driver declares for its other source file.  It is not under a
// directory named "include", which is where the interfaces of the kernel
// are and where the rule holds that whoever keeps a node takes a reference.
struct device_node;
int other_half_init(struct device_node *np);
