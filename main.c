#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h> // for close

const char* outer_map_name = "outer_map";

static struct bpf_object*
get_bpf_object(char* path) {
  struct bpf_object* obj = bpf_object__open(path);
  if (!obj) {
    printf("Failed to load bpf_object from %s\n", path);
    return NULL;
  }
  struct bpf_program* prog;
  enum bpf_prog_type prog_type;
  enum bpf_attach_type expected_attach_type;
  bpf_object__for_each_program(prog, obj) {
    const char* prog_name = bpf_program__title(prog, /*needs_copy*/ false);
    int err = libbpf_prog_type_by_name(prog_name, &prog_type, &expected_attach_type);
    if (err < 0) {
      printf("Failed to guess program type based on section name: %s\n", prog_name);
      return NULL;
    }
    bpf_program__set_type(prog, prog_type);
    bpf_program__set_expected_attach_type(prog, expected_attach_type);
  }
  return obj;
}

int load(struct bpf_object* obj) {
  struct bpf_map* outer_map = bpf_object__find_map_by_name(obj, outer_map_name);
  if (outer_map == NULL) {
    printf("Failed to find outer map!\n");
    return -1;
  }
  int inner_map_fd = bpf_create_map(
      BPF_MAP_TYPE_HASH, // type
      sizeof(__u32), // key_size
      sizeof(__u32), // value_size
      8, // max_entries
      0); // flag
  if (bpf_map__set_inner_map_fd(outer_map, inner_map_fd) != 0) {
    close(inner_map_fd);
    printf("Failed to set inner map fd!\n");
    return -1;
  }

  if (bpf_object__load(obj)) {
    close(inner_map_fd);
    printf("Failed to load bpf object: %ld\n", libbpf_get_error(obj));
    return -1;
  }
  close(inner_map_fd);
  return 0;
}

int get_map_fd(struct bpf_object* obj, const char* name) {
  struct bpf_map* map = bpf_object__find_map_by_name(obj, name);
  if (map == NULL) {
    printf("Failed to find map %s\n", name);
    return -1;
  }
  return bpf_map__fd(map);
}

int insert(struct bpf_object* obj) {
  int outer_map_fd = get_map_fd(obj, outer_map_name);
  if (outer_map_fd < 0) {
    printf("Failed to get outer map fd!\n");
    return -1;
  }
  int ret = 0;
  int inner_map_fd = bpf_create_map_name(
      BPF_MAP_TYPE_HASH, // type
      "inner_map", // name
      sizeof(__u32), // key_size
      sizeof(__u32), // value_size
      8, // max_entries
      0); // flag
  if (inner_map_fd < 0) {
    printf("Failed to create inner map!\n");
    return -1;
  }
  const __u32 inner_key = 12;
  const __u32 inner_value = 34;
  if (bpf_map_update_elem(
          inner_map_fd, &inner_key, &inner_value, 0 /* flag */)) {
    printf("Failed to insert into inner map!\n");
    goto err;
  }
  const __u32 outer_key = 42;
  if (bpf_map_update_elem(
          outer_map_fd, &outer_key, &inner_map_fd, 0 /* flag */)) {
    printf("Failed to insert into outer map!\n");
    goto err;
  }
  goto out;
err:
  ret = -1;
out:
  close(inner_map_fd); // Important!
  return ret;
}

int lookup(struct bpf_object* obj) {
  int outer_map_fd = get_map_fd(obj, outer_map_name);
  if (outer_map_fd < 0) {
    printf("Failed to get outer map fd!\n");
    return -1;
  }
  const __u32 outer_key = 42;
  __u32 inner_map_id;
  if (bpf_map_lookup_elem(outer_map_fd, &outer_key, &inner_map_id)) {
    printf("Failed to find inner map id!\n");
    return -1;
  }
  int inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
  if (inner_map_fd < 0) {
    printf("Failed to find inner map fd!\n");
    return -1;
  }
  const __u32 inner_key = 12;
  __u32 inner_value;
  int ret = 0;
  if (bpf_map_lookup_elem(inner_map_fd, &inner_key, &inner_value)) {
    printf("Failed to look up the value in inner map!\n");
    ret = -1;
  } else {
    printf("Inner value is %u!\n", inner_value);
    ret = 0;
  }
  close(inner_map_fd); // Important!
  return ret;
}

int delete_(struct bpf_object* obj) {
  int outer_map_fd = get_map_fd(obj, outer_map_name);
  if (outer_map_fd < 0) {
    printf("Failed to get outer map fd!\n");
    return -1;
  }
  const __u32 outer_key = 42;
  if (bpf_map_delete_elem(outer_map_fd, &outer_key)) {
    printf("Failed to delete inner map!\n");
    return -1;
  }
  return 0;
}

int main() {
  struct rlimit lck_mem = {};
  lck_mem.rlim_cur = RLIM_INFINITY;
  lck_mem.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
    printf("Can't change rlimit for locked memory!\n");
    return -1;
  }
  char* bpf_file = "./test_bpf.o";
  struct bpf_object* obj = get_bpf_object(bpf_file);
  if (obj == NULL) {
    return -1;
  }
  if (load(obj)) {
    printf("Failed to load BPF object!\n");
    return -1;
  }
  printf("Loaded\n");
  if (insert(obj)) {
    return -1;
  }
  printf("Inserted\n");
  if (lookup(obj)) {
    return -1;
  }
  if (delete_(obj)) {
    return -1;
  }
  printf("Deleted\n");

  if (bpf_object__unload(obj)) {
    printf("Failed to unload bpf object!\n");
    return -1;
  }
  printf("Unloaded\n");
  return 0;
}
