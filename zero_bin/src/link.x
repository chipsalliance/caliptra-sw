SECTIONS
{
  .text : ALIGN(4)
  {
      _stext = .;

      KEEP(*(.init .init.*));
      *(.text .text.*);
      KEEP(*(.vectors))

      . = ALIGN(4);
      _etext = .;
  } > REGION_TEXT
}
