#include <assert.h>
#include "../lib/http_chunks.h"
/* helper used only by the test harness */
static int fuzz_chunk_entry(const char *d, size_t n)
{
  struct chunk_state st = {0, 0, 0};
  return chunk_decode(&st, d, n);
}
int main(void)
{
  assert(chunk_read_size("10\r\n", 4) == 16);
  fuzz_chunk_entry("1\r\nA", 4);
  return 0;
}
