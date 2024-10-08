#include "../include/load.h"

int remove_lkm(){

  char command[10] = "rmmod lkm";

  int result = system(command);
  if(result == -1){
    log_error("Error executing rmmod");
    return -1;
  }
  return WEXITSTATUS(result);
}


int is_lkm_loaded(const char* name){

  DIR *dir = opendir("/sys/module/");

  if(!dir){
    log_error("Error opening the /sys/module directory");
    return -1;
  }

  struct dirent *entry;

  while ((entry = readdir(dir)) != NULL){
    if(strcmp(entry->d_name, name) == 0){
       closedir(dir);
       puts("Module already loaded!");
       return 1;
    }
  }

  closedir(dir);
  return 0;

}

int load_lkm(const unsigned char *lkm,ssize_t total_size){

    int fdlkm = memfd_create("lkmmod", 0);
    if (fdlkm < 0) {
      log_error("memfd_create failed");
      return -1;
  }
   ssize_t written_bytes = write(fdlkm, lkm, total_size);
    if (written_bytes < 0) {
      log_error("Error writing to memfd");
      close(fdlkm);
      return -1;
    } else if (written_bytes != total_size) {
      log_error("Incomplete write to memfd (Expected %zu, wrote %zd)\n)", total_size, written_bytes);
      close(fdlkm);
      return -1;
    }
    if (syscall(SYS_finit_module, fdlkm, "", 0) != 0) {
      log_error("Failed to init module");
      close(fdlkm);
      return -1;
    }

  printf("Module loaded successfully\n");
  close(fdlkm);

  return 0;
}
