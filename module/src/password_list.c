#include "password_list.h"
#include <linux/kernel.h>

struct list_head passwords;

void password_list_init(struct list_head *head)
{
    INIT_LIST_HEAD(head);
}

int password_list_add(struct list_head *head, const char *password)
{
    password_node_t *new_node;

    if (!password || strlen(password) >= MAX_PASSWORD_LEN) {
        return -EINVAL;
    }
    new_node = kmalloc(sizeof(password_node_t), GFP_KERNEL);
    if (!new_node) {
        return -ENOMEM;
    }
    strncpy(new_node->password, password, MAX_PASSWORD_LEN);
    new_node->password[MAX_PASSWORD_LEN - 1] = '\0';
    list_add_tail(&new_node->list, head);
    return 0;
}

int password_list_remove(struct list_head *head, const char *password)
{
    password_node_t *node, *tmp;

    if (!password) {
        return -EINVAL;
    }
    list_for_each_entry_safe(node, tmp, head, list) {
        if (strncmp(node->password, password, MAX_PASSWORD_LEN) == 0) {
            list_del(&node->list);
            kfree(node);
            return 0;
        }
    }
    return -ENOENT;
}

void password_list_clear(struct list_head *head)
{
    password_node_t *node, *tmp;

    list_for_each_entry_safe(node, tmp, head, list) {
        list_del(&node->list);
        kfree(node);
    }
}

void password_list_print(struct list_head *head)
{
    password_node_t *node;
    list_for_each_entry(node, head, list) {
        pr_info("Password: %s\n", node->password);
    }
}
