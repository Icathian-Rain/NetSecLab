//
// Created by yll20 on 2023/04/19.
//

#ifndef HUSTVPN_UTILS_H
#define HUSTVPN_UTILS_H

#include <string>
#include <vector>

#define CHK_ERR(err, s) if ((err)==-1) { perror(s); exit(1); }
#define BUFFER_SIZE 4096

std::string get_ip_by_cidr(const std::string& cidr, int index);
int cidr_to_ip_and_mask(const char *cidr, uint32_t *ip, uint32_t *mask);
std::string int_to_ip(uint32_t ip_addr);


#endif //HUSTVPN_UTILS_H