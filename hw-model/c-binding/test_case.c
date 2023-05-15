

#include "caliptra_model.h"

#define MBOX_UDS_ADDR 0x30030200
#define MBOX_FE_ADDR 0x30030230
#define MBOX_FUSE_DONE_ADDR 0x300303f0
#define MBOX_ADDR_BASE 0x30020000
#define MBOX_ADDR_LOCK MBOX_ADDR_BASE
#define MBOX_ADDR_CMD (MBOX_ADDR_BASE + 0x00000008)
#define MBOX_ADDR_DLEN (MBOX_ADDR_BASE + 0x0000000C)
#define MBOX_ADDR_DATAIN (MBOX_ADDR_BASE + 0x00000010)
#define MBOX_ADDR_DATAOUT (MBOX_ADDR_BASE + 0x00000014)
#define MBOX_ADDR_EXECUTE (MBOX_ADDR_BASE + 0x00000018)
#define MBOX_ADDR_STATUS (MBOX_ADDR_BASE + 0x0000001c)

#define MBOX_STATUS_BUSY 0
#define MBOX_STATUS_DATA_READY 1
#define MBOX_STATUS_CMD_COMPLETE 2
#define MBOX_STATUS_CMD_FAILURE 3

static struct caliptra_buffer read_file_or_die(const char* path) {
  // TODO: Read the file at path into a heap-allocated buffer and return it
}

int main(int argc, const char* argv[]) {
  struct caliptra_model* model;

  struct caliptra_model_init_params init_params = {
      .rom = read_file_or_die("caliptra_rom.bin"),
  };

  caliptra_model_init_sw_emulator(init_params, &model);

  int i = 0;
  while (!caliptra_model_ready_for_fuses(model)) {
    caliptra_model_step(model);
  }

  for (int i = 0; i < 12; i++) {
    caliptra_model_apb_write_u32(model, MBOX_UDS_ADDR + i * 4, 0xcafebabe + i);
  }

  for (int i = 0; i < 24; i++) {
    caliptra_model_apb_write_u32(model, MBOX_FE_ADDR + i * 4, 0xcafebabe + i);
  }

  caliptra_model_apb_write_u32(model, MBOX_FUSE_DONE_ADDR, 1);

  // Lock the mailbox
  uint32_t locked;
  do {
    caliptra_model_apb_read_u32(model, MBOX_ADDR_LOCK, &locked);
  } while (locked);

  // Write something to the mailbox
  caliptra_model_apb_write_u32(model, MBOX_ADDR_CMD, 1);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DLEN, 28);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x00000000);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x11111111);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x22222222);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x33333333);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x44444444);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x55555555);
  caliptra_model_apb_write_u32(model, MBOX_ADDR_DATAIN, 0x66666666);

  caliptra_model_apb_write_u32(model, MBOX_ADDR_STATUS, MBOX_STATUS_DATA_READY);

  caliptra_model_apb_write_u32(model, MBOX_ADDR_EXECUTE, 1);

  while (!caliptra_model_exit_requested(model)) {
    caliptra_model_step(model);
  }
}