#ifndef PASSWORD_LIST_H
#define PASSWORD_LIST_H

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MAX_PASSWORD_LEN 64

extern struct list_head passwords;

typedef struct password_node {
    char password[MAX_PASSWORD_LEN];
    struct list_head list;
} password_node_t;

void password_list_init(struct list_head *head);
int password_list_add(struct list_head *head, const char *password);
int password_list_remove(struct list_head *head, const char *password);
void password_list_clear(struct list_head *head);
void password_list_print(struct list_head *head);

#endif // PASSWORD_LIST_H
