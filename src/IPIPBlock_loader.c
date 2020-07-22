#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <time.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"
#include "common.h"

// TC CMD sizes.
#define CMD_MAX 2048
#define CMD_MAX_TC 256

// Initialize static variables.
static uint8_t cont = 1;
static int blacklist_map_fd;

// TC program file name.
const char TCFile[] = "/etc/IPIPBlock/IPIPBlock_filter.o";

// Maps.
const char *map_blacklist = BASEDIR_MAPS "/blacklist_map";

// Extern error number.
extern int errno;

// Signal function.
void signHdl(int tmp)
{
    // Set cont to 0 which will stop the while loop and the program.
    cont = 0;
}

int open_map(const char *name)
{
    // Initialize FD.
    int fd;

    // Get map objective.
    fd = bpf_obj_get(name);

    // Check map FD.
    if (fd < 0)
    {
        fprintf(stderr, "Error getting map. Map name => %s\n", name);

        return fd;
    }

    // Return FD.
    return fd;
}

int tc_ingress_attach_bpf(const char *dev, const char *bpf_obj, const char *sec_name)
{
    // Initialize variables.
    char cmd[CMD_MAX];
    int ret = 0;

    // Delete clsact which also deletes existing filters.

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc qdisc del dev %s clsact 2> /dev/null", dev);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (!WIFEXITED(ret)) 
    {
        fprintf(stderr, "Error attaching TC ingress filter. Cannot execute TC command when removing clsact. Command => %s and Return Error Number => %d.\n", cmd, WEXITSTATUS(ret));
    }

    // Create clsact.

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc qdisc add dev %s clsact", dev);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error attaching TC ingress filter. TC cannot create a clsact. Command => %s and Return Error Number => %d.\n", cmd, WEXITSTATUS(ret));

        exit(1);
    }

    // Attach to ingress filter.

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc filter add dev %s ingress prio 1 handle 1 bpf da obj %s sec %s", dev, bpf_obj, sec_name);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error attaching TC ingress filter. TC cannot attach to filter. Command => %s and Return Error Number => %d.\n", cmd, WEXITSTATUS(ret));

        exit(1);
    }

    // Return error or not.
    return ret;
}

int tc_remove_ingress_filter(const char* dev)
{
    // Initialize starting variables.
    char cmd[CMD_MAX];
    int ret = 0;

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc filter delete dev %s ingress", dev);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error detaching TC ingress filter. Command => %s and Return Error Number => %d.\n", cmd, ret);

        exit(1);
    }

    // Return error or not.
    return ret;
}

int bpf_map_get_next_key_and_delete(int fd, const void *key, void *next_key, int *delete)
{
    // Get the next key in the BPF map.
    int res = bpf_map_get_next_key(fd, key, next_key);

    // Check to see if we should delete the item.
    if (*delete) 
    {
        bpf_map_delete_elem(fd, key);
        *delete = 0;
    }

    return res;
}

void UpdateList()
{
    // Open list file.
    FILE *fp = fopen("/etc/IPIPBlock/list.conf", "r");

    // Check if file opened successfully.
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening list file :: %s\n", strerror(errno));

        return;
    }

    // Loop through the current map and delete each entry.
    uint32_t key = -1;
    uint32_t prevkey = -1;
    int delete = 0;

    while(bpf_map_get_next_key_and_delete(blacklist_map_fd, &prevkey, &key, &delete) == 0)
    {
        delete = 1;

        prevkey = key;
    }

    // Parse config file for each line and add to BPF map.
    char line[32];
    char *ptr;

    while (fgets(line, sizeof(line), fp))
    {
        // Check line length.
        if (strlen(line) < 4)
        {
            continue;
        }

        ptr = strtok(line, "\n");

        // Convert IP to decimal and host byte order to store.
        uint32_t ip = inet_addr(ptr);
        uint8_t val = 1;

        // Attempt to update BPF map.
        if (bpf_map_update_elem(blacklist_map_fd, &ip, &val, BPF_ANY) != 0)
        {
            fprintf(stderr, "Error adding %s (%" PRIu32 ") to BPF map.\n", ptr, ip);
        }
    }
}

int main(int argc, char *argv[])
{
    // Check argument count.
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Interface>\n", argv[0]);

        exit(1);
    }

    // Initialize variables.
    int err, ifindex;

    // Get interface index.
    ifindex = if_nametoindex(argv[1]);

    // Check if interface is valid.
    if (ifindex <= 0)
    {
        fprintf(stderr, "Error loading interface (%s).\n", argv[1]);

        exit(1);
    }

    // Attempt to attach to ingress filter.
    err = tc_ingress_attach_bpf(argv[1], TCFile, "ingress");

    if (err)
    {
        exit(err);
    }

    // Get MAC map.
    blacklist_map_fd = open_map(map_blacklist);

    if (blacklist_map_fd < 0)
    {
        // Attempt to remove TC filter since map failed.
        tc_remove_ingress_filter(argv[1]);

        exit(blacklist_map_fd);
    }

    // Signal calls so we can shutdown program.
    signal(SIGINT, signHdl);
    signal(SIGTERM, signHdl);
    signal(SIGKILL, signHdl);

    // Debug.
    fprintf(stdout, "Starting IPIP Block TC ingress program.\n");

    // Get current time so we can update file.
    time_t lastupdated = time(NULL);

    // Update list immediately.
    UpdateList();

    // Loop!
    while (cont)
    {
        // Get new time.
        time_t curtime = time(NULL);

        // Check if it has been two minutes since last update.
        if (curtime > (lastupdated + 120))
        {
            // Update BPF map list.
            UpdateList();

            // Change last updated time.
            lastupdated = time(NULL);
        }

        // We sleep every second.
        sleep(1);
    }

    // Debug.
    fprintf(stdout, "Cleaning up...\n");

    // Remove TC egress filter.
    err = tc_remove_ingress_filter(argv[1]);

    // Check for errors.
    if (err)
    {
        exit(err);
    }

    exit(0);
}