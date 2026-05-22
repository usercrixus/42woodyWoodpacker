SECTIONS
{
  .woody_stub ALIGN(16) :
  {
    __start_.woody_stub = .;
    KEEP(*(.text.woody_stub.entry))
    KEEP(*(.text.woody_stub))
    KEEP(*(.rodata.woody_stub))
    KEEP(*(.data.woody_stub))
    KEEP(*(.bss.woody_stub))
    __stop_.woody_stub = .;
  }
}
INSERT AFTER .text;
