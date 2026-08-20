# moddect

A hidden module detector, which compares the allocations in the module area to
the known allocations (like the ones in the module list) and alerts if an
unknown allocation is found.

The detector was tested mostly against
[KoviD](https://github.com/carloslack/KoviD). Any functionality is not
guaranteed, use at your own risk.

## Installation

Clone the repo and compile the module.

After the compilation, the module can be loaded with:
```bash
modprobe detector.ko
```

## Usage

The module runs the scan in the init function for now, but a `procfs`
implementation is in development. For now, the scan result is printed into the
kernel ring buffer and can be read with `dmesg` or from the journal
alternatively.

It is advised to run the module in a virtual machine.
